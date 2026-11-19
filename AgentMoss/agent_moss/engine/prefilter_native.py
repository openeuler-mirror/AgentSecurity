"""Owned BLOCK databases using the public Hyperscan/Ultrascan C ABI.

Backend names are deployment declarations, never inferred from hs_version.
Compilation uses the library's default misc allocator and libc.free for its
serialized buffer. Hosts that change that allocator must build in a separate
interpreter process. No allocator is changed here. Successful library bindings
stay loaded; only an open reference acquired by a failed initialization closes.
"""
import ctypes as C
import os
import platform
import re
import threading

from .prefilter_contract import MAX_EXPRESSIONS, NATIVE_FLAGS, NATIVE_MODE


class NativeError(RuntimeError):
    def __init__(self, message, *, stage=None, status=None):
        self.stage = stage
        self.status = status
        detail = f"{stage}: " if stage else ""
        detail += message
        if status is not None:
            detail += f" (status={status})"
        super().__init__(detail)


class NativeLoadError(NativeError):
    pass


class NativeCompileError(NativeError):
    def __init__(self, message, *, expression_index=None, stage=None, status=None):
        self.expression_index = expression_index
        super().__init__(message, stage=stage, status=status)


class NativeScanError(NativeError):
    pass


class _CompileError(C.Structure):
    _fields_ = [("message", C.c_char_p), ("expression", C.c_int)]


class _PlatformInfo(C.Structure):
    _fields_ = [("tune", C.c_uint), ("cpu_features", C.c_ulonglong),
                ("reserved1", C.c_ulonglong), ("reserved2", C.c_ulonglong)]


_Pointer = C.c_void_p
_PointerOut = C.POINTER(_Pointer)
_ErrorPointer = C.POINTER(_CompileError)
_Callback = C.CFUNCTYPE(C.c_int, C.c_uint, C.c_ulonglong, C.c_ulonglong,
                       C.c_uint, _Pointer)
_UINT_MAX = 2 ** 32 - 1


def _function(handle, name, arguments, result=C.c_int):
    function = getattr(handle, name)
    function.argtypes = arguments
    function.restype = result
    return function


def _close_failed_library(handle):
    # CDLL does not release dlopen references on collection. Decrement exactly
    # the reference acquired by this failed initializer, never another owner's.
    close = _function(C.CDLL(None), "dlclose", [_Pointer])
    status = close(handle._handle)
    if status != 0:
        raise NativeLoadError("failed to close rejected library reference", stage="dlclose", status=status)


def _resolve_library_path(path, architecture):
    """Resolve ordinary deployment paths without registering a dlopen alias.

    Basenames use plain LD_LIBRARY_PATH directories, then the system cache.
    Special ELF search rules (RPATH, dynamic tokens, hwcaps) require an explicit
    file path instead; we never fall back to passing an unresolved SONAME.
    """
    if os.path.dirname(path):
        return os.path.realpath(path)
    message = f"cannot resolve native library {path!r}; set AGENT_MOSS_ACCEL_LIB to an absolute file path"
    search_path = os.environ.get("LD_LIBRARY_PATH", "")
    if search_path:
        for directory in re.split("[:;]", search_path):
            if "$" in directory:
                raise NativeLoadError(message, stage="resolve")
            candidate = os.path.join(directory or os.curdir, path)
            if os.path.isfile(candidate):
                return os.path.realpath(candidate)

    # Read-only discovery, only on a cache miss. No shell, compiler or ldconfig
    # mutation; limit execution time and the listing accepted for parsing.
    import subprocess
    abi = {"x86_64": "x86-64", "aarch64": "AArch64"}[architecture]
    for executable in ("/sbin/ldconfig", "/usr/sbin/ldconfig"):
        try:
            result = subprocess.run([executable, "-p"], stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    env={"LC_ALL": "C", "LANG": "C"}, timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode != 0 or len(result.stdout) > 4 * 1024 * 1024:
            continue
        for line in os.fsdecode(result.stdout).splitlines():
            entry = re.fullmatch(r"\s*(\S+)\s+\(([^)]*)\)\s+=>\s+(/.+?)\s*", line)
            if entry is None or entry[1] != path:
                continue
            flags = [flag.strip() for flag in entry[2].split(",")]
            if flags[:2] != ["libc6", abi] or "hwcap" in entry[2].lower():
                continue
            if os.path.isfile(entry[3]):
                return os.path.realpath(entry[3])
        break
    raise NativeLoadError(message, stage="resolve")


class _Binding:
    def __init__(self, path, backend, architecture, system):
        self.compile_lock = threading.Lock()
        self.compiler_bound = False
        # This constructor runs only on a successful-cache miss. Resolve the
        # file now so the linker cannot retain a rejected symlink's
        # name as an alias of a still-loaded dependency (for example libm).
        load_path = _resolve_library_path(path, architecture)
        # Preserve OSError's loader diagnostic (missing file, dependency or ELF).
        self.handle = C.CDLL(load_path)
        try:
            self._bind_runtime(path, backend, architecture, system)
        except BaseException:
            _close_failed_library(self.handle)
            raise

    def _bind_runtime(self, path, backend, architecture, system):
        try:
            version = _function(self.handle, "hs_version", [], C.c_char_p)
            valid = _function(self.handle, "hs_valid_platform", [])
            self.deserialize = _function(self.handle, "hs_deserialize_database",
                                         [C.c_char_p, C.c_size_t, _PointerOut])
            self.alloc_scratch = _function(self.handle, "hs_alloc_scratch",
                                           [_Pointer, _PointerOut])
            self.scan = _function(self.handle, "hs_scan",
                                  [_Pointer, C.c_char_p, C.c_uint, C.c_uint,
                                   _Pointer, _Callback, _Pointer])
            self.free_scratch = _function(self.handle, "hs_free_scratch", [_Pointer])
            self.free_database = _function(self.handle, "hs_free_database", [_Pointer])
        except AttributeError as exc:
            raise NativeLoadError(f"missing runtime symbol: {exc}", stage="bind") from exc
        status = valid()
        if status != 0:
            raise NativeLoadError("unsupported native platform", stage="valid_platform", status=status)
        raw_version = version()
        text = raw_version.decode("ascii", "replace") if raw_version else ""
        match = re.fullmatch(r"(\d+\.\d+\.\d+)(?:\s+(.*))?", text)
        if match is None:
            raise NativeLoadError("unrecognized native version", stage="version")
        self.metadata = {
            "backend": backend, "version": text, "version_numeric": match[1],
            "build_date": match[2], "architecture": architecture, "system": system,
            "library_path": path, "runtime_available": True, "valid_platform_status": status,
        }

    def bind_compiler(self):
        with self.compile_lock:
            if self.compiler_bound:
                return
            try:
                compile_multi = _function(self.handle, "hs_compile_multi", [
                    C.POINTER(C.c_char_p), C.POINTER(C.c_uint), C.POINTER(C.c_uint),
                    C.c_uint, C.c_uint, C.POINTER(_PlatformInfo), _PointerOut,
                    C.POINTER(_ErrorPointer)])
                free_error = _function(self.handle, "hs_free_compile_error", [_ErrorPointer])
                serialize = _function(self.handle, "hs_serialize_database",
                                      [_Pointer, _PointerOut, C.POINTER(C.c_size_t)])
            except AttributeError as exc:
                raise NativeCompileError(f"missing compiler symbol: {exc}", stage="bind") from exc
            self.libc = C.CDLL(None)
            self.free_buffer = _function(self.libc, "free", [_Pointer], None)
            self.compile_multi = compile_multi
            self.free_compile_error = free_error
            self.serialize = serialize
            self.compiler_bound = True


class _ProcessState:
    def __init__(self):
        self.pid = os.getpid()
        self.lock = threading.Lock()
        self.bindings = {}


_state = _ProcessState()


def _process_state():
    global _state
    # Check before touching any inherited lock, including during initialization.
    if _state.pid != os.getpid():
        _state = _ProcessState()
    return _state


class NativeLibrary:
    """One process-owned view of a cached (path, declared backend) library.

    None uses AGENT_MOSS_ACCEL_LIB or libhs.so.5. Basenames are discovered in
    ordinary LD_LIBRARY_PATH directories and the native-architecture system
    ldconfig cache; other ELF search configurations require a file path.
    Successful bindings keep their handles regardless of later path changes.
    """
    def __init__(self, path: str | None, *, backend: str | None = None):
        system = platform.system()
        architecture = platform.machine().lower()
        architecture = {"amd64": "x86_64", "arm64": "aarch64"}.get(architecture, architecture)
        if system != "Linux" or architecture not in ("x86_64", "aarch64"):
            raise NativeLoadError("unsupported native operating system or architecture", stage="platform")
        declared = backend if backend is not None else os.environ.get("AGENT_MOSS_ACCEL_BACKEND")
        self._backend_source = "config" if declared is not None else "platform_default"
        if declared is None:
            declared = {"x86_64": "hyperscan", "aarch64": "ultrascan"}[architecture]
        if declared not in ("hyperscan", "ultrascan"):
            raise NativeLoadError("backend must be hyperscan or ultrascan", stage="config")
        path = path if path is not None else os.environ.get("AGENT_MOSS_ACCEL_LIB", "libhs.so.5")
        if not isinstance(path, str) or not path or "\x00" in path:
            raise NativeLoadError("library path must be a nonempty string", stage="config")
        # The cache key is lexical; successful hits never resolve/stat symlinks.
        path = os.path.abspath(path) if os.path.dirname(path) else path
        state = _process_state()
        with state.lock:
            key = (path, declared)
            binding = state.bindings.get(key)
            if binding is None:
                binding = _Binding(path, declared, architecture, system)
                state.bindings[key] = binding
        self._binding = binding
        self._pid = state.pid

    def _check_owner(self, error_type):
        if self._pid != os.getpid():
            raise error_type("inherited library must be rebuilt after fork", stage="fork")

    def info(self) -> dict:
        self._check_owner(NativeLoadError)
        result = dict(self._binding.metadata, backend_source=self._backend_source)
        result["compiler_available"] = all(hasattr(self._binding.handle, name) for name in (
            "hs_compile_multi", "hs_free_compile_error", "hs_serialize_database"))
        return result

    def compile(self, expressions: list[str]) -> bytes:
        self._check_owner(NativeCompileError)
        if not isinstance(expressions, list) or not 1 <= len(expressions) <= MAX_EXPRESSIONS:
            raise NativeCompileError("invalid expression count", stage="input")
        encoded = []
        for index, expression in enumerate(expressions):
            if not isinstance(expression, str) or not expression.isascii() or "\x00" in expression:
                raise NativeCompileError("expression must be ASCII without NUL", stage="input",
                                         expression_index=index)
            encoded.append(expression.encode("ascii"))
        binding = self._binding
        binding.bind_compiler()
        count = len(encoded)
        sources = (C.c_char_p * count)(*encoded)
        flags = (C.c_uint * count)(*([NATIVE_FLAGS] * count))
        ids = (C.c_uint * count)(*range(count))
        database, buffer = _Pointer(), _Pointer()
        error, length = _ErrorPointer(), C.c_size_t()
        try:
            status = binding.compile_multi(sources, flags, ids, count, NATIVE_MODE,
                                           None, C.byref(database), C.byref(error))
            if status != 0 or not database or error:
                index = None
                message = "native expression compilation failed"
                if error:
                    index = error.contents.expression
                    index = index if 0 <= index < count else None
                    message = (error.contents.message or b"native expression compilation failed").decode(
                        "utf-8", "replace")
                raise NativeCompileError(message, stage="compile", status=status, expression_index=index)
            status = binding.serialize(database, C.byref(buffer), C.byref(length))
            if status != 0 or not buffer or not length.value:
                raise NativeCompileError("database serialization failed", stage="serialize", status=status)
            return C.string_at(buffer, length.value)
        finally:
            try:
                if buffer:
                    binding.free_buffer(buffer)
            finally:
                try:
                    if error:
                        binding.free_compile_error(error)
                finally:
                    if database:
                        binding.free_database(database)

    def load(self, blob: bytes, expression_count: int) -> "NativeDatabase":
        self._check_owner(NativeLoadError)
        if (not isinstance(expression_count, int) or isinstance(expression_count, bool)
                or not 1 <= expression_count <= MAX_EXPRESSIONS):
            raise NativeLoadError("invalid expression count", stage="input")
        if not isinstance(blob, bytes) or not blob:
            raise NativeLoadError("database must be nonempty bytes", stage="input")
        binding = self._binding
        database, scratch = _Pointer(), _Pointer()
        try:
            status = binding.deserialize(blob, len(blob), C.byref(database))
            if status != 0 or not database:
                raise NativeLoadError("database deserialization failed", stage="deserialize", status=status)
            status = binding.alloc_scratch(database, C.byref(scratch))
            if status != 0 or not scratch:
                raise NativeLoadError("scratch allocation failed", stage="alloc_scratch", status=status)
            return NativeDatabase(self, database, scratch, expression_count)
        except BaseException:
            try:
                if scratch:
                    binding.free_scratch(scratch)
            finally:
                if database:
                    binding.free_database(database)
            raise


class NativeDatabase:
    """Owns one db/scratch pair; scan and close share a lock, never a callback."""
    def __init__(self, library, database, scratch, expression_count):
        self._lock = threading.Lock()
        self._pid = os.getpid()
        self._library = library  # Keep code and bindings alive as long as handles.
        self._database = database
        self._scratch = scratch
        self._expression_count = expression_count

    def scan(self, data: bytes) -> set[int]:
        if self._pid != os.getpid():
            raise NativeScanError("inherited database must be rebuilt after fork", stage="fork")
        if not isinstance(data, bytes) or len(data) > _UINT_MAX:
            raise NativeScanError("scan requires bytes with length <= UINT_MAX", stage="input")
        with self._lock:
            if not self._database:
                raise NativeScanError("database is closed", stage="scan")
            hits = set()
            callback_error = None

            @_Callback
            def on_match(ident, start, end, flags, context):
                nonlocal callback_error
                try:
                    if not 0 <= ident < self._expression_count:
                        raise ValueError(f"unknown expression id {ident}")
                    hits.add(ident)
                    return 0
                except BaseException as exc:
                    callback_error = exc
                    return 1

            try:
                status = self._library._binding.scan(self._database, data, len(data), 0,
                                                     self._scratch, on_match, None)
            except Exception as exc:
                raise NativeScanError(f"native scan failed: {exc}", stage="scan") from exc
            if callback_error is not None:
                raise NativeScanError(f"callback failed: {callback_error}", stage="scan",
                                      status=status) from callback_error
            if status != 0:
                raise NativeScanError("native scan did not complete", stage="scan", status=status)
            return hits

    def close(self):
        if self._pid != os.getpid():
            # Inherited copies are never used/freed; the child rebuilds its own.
            self._scratch = self._database = None
            return
        with self._lock:
            scratch, database = self._scratch, self._database
            self._scratch = self._database = None
            try:
                if scratch:
                    self._library._binding.free_scratch(scratch)
            finally:
                if database:
                    self._library._binding.free_database(database)

    def __del__(self):
        try:
            self.close()
        except BaseException:
            # Includes a partially constructed object or interpreter shutdown.
            pass
