"""Render the L3 security prompt and apply the configured input budget."""

from collections.abc import Callable
from dataclasses import dataclass

from ..infra.config import LLMPromptBudgetConfig, get_llm_prompt_history_max_turns
from ..infra.prompt_templates import get_security_judge_prompt


_NO_PROMPT_HISTORY = "（未提供历史意图）"
_HISTORY_AUTHORIZATION = (
    "被省略或被截断的历史不能作为授权依据。\n"
    "“继续”只指代可见的前文；如果可见前文不足以确认指代目标或授权范围，"
    "应在 reason 中说明依据不足，并按最小权限原则判断需要该授权的动作。\n"
    "当前用户请求中明确写出的授权仍然有效，按其可见的目标和限制判断。"
)
_DETAIL_MARKER = "...[省略 {} 字符]..."
_SESSION_SIZE_MARKER = "（当前用户请求因长度上限已截断，省略 {} 字符，以下为头尾内容）"
_SESSION_BUDGET_MARKER = "（当前用户请求因 token 预算已截断，省略 {} 字符，以下为头尾内容）"
_SCRIPT_SIZE_MARKER = "（脚本分析因长度上限已截断，省略 {} 字符）"
_SCRIPT_BUDGET_MARKER = "（脚本分析因 token 预算已截断，省略 {} 字符）"


@dataclass(frozen=True)
class PreparedL3Prompt:
    text: str
    stage: str
    code: str = ""
    floor_estimate: int | None = None


def _truncate(text: str, max_chars: int, marker: str) -> str:
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    head = max(1, max_chars * 3 // 5)
    tail = max_chars - head
    suffix = text[-tail:] if tail else ""
    return text[:head] + marker.format(len(text) - max_chars) + suffix


def truncate_detail(detail: str, max_chars: int) -> str:
    return _truncate(detail, max_chars, _DETAIL_MARKER)


def _estimate_chars(chars: int) -> int:
    return chars * 2 // 5 + 1


def estimate_tokens(text: str) -> int:
    return _estimate_chars(len(text))


def format_action_history(
    action_history: list[dict[str, object]], max_items: int = 0, max_chars: int = 0,
    *, budget_chars: int | None = None,
) -> str:
    if not action_history:
        return "（无历史动作）"

    items = action_history[-max_items:] if max_items > 0 else action_history
    omitted_items = len(action_history) - len(items)
    lines = []
    if omitted_items:
        lines.append(f"（更早的 {omitted_items} 条历史动作已省略）")
    for i, action in enumerate(items, 1):
        if isinstance(action, dict):
            name = action.get("name", action.get("action_type", "未知"))
            detail = action.get("action_detail", "")
            if detail:
                original = str(detail)
                shown = truncate_detail(original, max_chars)
                if budget_chars is not None and budget_chars != max_chars:
                    # A budget trim only helps when it is shorter with the marker included.
                    shown = min(shown, truncate_detail(original, budget_chars), key=len)
                lines.append(f"  {i}. {name}: {shown}")
            else:
                lines.append(f"  {i}. {name}")
        else:
            lines.append(f"  {i}. {action}")
    return "\n".join(lines)


@dataclass(frozen=True)
class _HistoryTurn:
    number: int
    text: str
    action_types: str


def _visible_turns(
    prompt_history: list[dict[str, object]] | None, max_turns: int,
) -> tuple[list[_HistoryTurn], int]:
    """Return the visible turn window and how many earlier non-empty turns it omitted."""
    history = prompt_history or []
    first = max(0, len(history) - max_turns) if max_turns > 0 else 0
    omitted = 0
    turns = []
    for index, turn in enumerate(history):
        if not isinstance(turn, dict):
            continue
        text = turn.get("text", "")
        if not isinstance(text, str):
            continue
        text = text.strip()
        actions = turn.get("actions")
        action_types = []
        if isinstance(actions, list):
            for action in actions:
                if isinstance(action, dict):
                    action_type = action.get("action_type")
                    if isinstance(action_type, str) and action_type:
                        action_types.append(action_type)
        if not (text or action_types):
            continue
        if index < first:
            omitted += 1
            continue
        turns.append(_HistoryTurn(index + 1, text, ", ".join(action_types)))
    return turns, omitted


def _history_lines(
    turns: list[_HistoryTurn], max_chars: int, old_chars: int, recent: int,
) -> tuple[list[str], bool]:
    old_intents = max(0, sum(bool(turn.text) for turn in turns) - recent)
    lines = []
    has_truncation = False
    for turn in turns:
        if not turn.text:
            lines.append(f"  第{turn.number}轮动作: {turn.action_types}")
            continue
        limit = old_chars if old_intents else max_chars
        old_intents = max(0, old_intents - 1)
        text = turn.text[:limit]
        if len(text) < len(turn.text):
            text += "（本段已按 token 预算截断）" if limit < max_chars else "（本段因长度上限已截断）"
            has_truncation = True
        actions = f"  → 动作: {turn.action_types}" if turn.action_types else ""
        lines.append(f"  第{turn.number}轮用户意图: {text}{actions}")
    return lines, has_truncation


def format_prompt_history(
    prompt_history: list[dict[str, object]] | None,
    max_text_chars: int = 500,
    max_turns: int | None = None,
) -> str:
    """Format the latest raw turn window, retaining the original turn numbers."""
    turns, omitted = _visible_turns(
        prompt_history, get_llm_prompt_history_max_turns() if max_turns is None else max_turns,
    )
    lines, _ = _history_lines(turns, max_text_chars, max_text_chars, len(turns))
    if omitted:
        lines.insert(0, _history_window_omission(omitted))
    return "\n".join(lines) if lines else _NO_PROMPT_HISTORY


def _history_window_omission(omitted: int) -> str:
    return f"（因历史窗口上限省略 {omitted} 轮更早历史意图）"


def _history_omission(intents: int, actions_only: int) -> str:
    parts = []
    if intents:
        parts.append(f"{intents} 轮历史意图")
    if actions_only:
        parts.append(f"{actions_only} 轮动作摘要")
    return f"（因 token 预算已省略 {'、'.join(parts)}）"


def _oldest_turns_to_omit(
    turns: list[_HistoryTurn], lines: list[str], render: Callable[..., str], token_limit: int, window_prefix: str,
) -> int:
    # Count the history suffix and its notices without rendering the full prompt
    # at every step for unlimited histories.
    current_chars = len(render())
    base_chars = len(render(prompt_history_text=window_prefix))
    with_guidance_chars = len(render(prompt_history_text=window_prefix, history_authorization=_HISTORY_AUTHORIZATION))
    remaining_chars = sum(len(line) + 1 for line in lines)
    shortest_chars = current_chars
    best = 0
    omitted_intents = 0
    for omitted, (turn, line) in enumerate(zip(turns, lines, strict=True), 1):
        remaining_chars -= len(line) + 1
        omitted_intents += bool(turn.text)
        marker = _history_omission(omitted_intents, omitted - omitted_intents)
        candidate_chars = (with_guidance_chars if omitted_intents else base_chars) + len(marker) + remaining_chars
        if candidate_chars < shortest_chars:
            shortest_chars = candidate_chars
            best = omitted
        if _estimate_chars(candidate_chars) <= token_limit:
            return omitted
    # Even a one-character saving can help a later trim cross the token threshold.
    return best


def _truncate_to_room(
    original: str, displayed: str, minimum: int, maximum: int, room: int, marker: str,
) -> str:
    maximum = min(maximum, len(original))
    if maximum <= minimum:
        return displayed
    smallest = _truncate(original, minimum, marker)
    if len(smallest) >= len(displayed):
        return displayed
    if len(smallest) > room:
        return smallest

    # Find the largest amount of retained source text that fits, including the
    # omission marker. The full source is handled separately because it has no marker.
    low = minimum
    high = min(maximum, len(original) - 1, room)
    while low < high:
        midpoint = (low + high + 1) // 2
        chars = midpoint + len(marker.format(len(original) - midpoint))
        if chars <= room:
            low = midpoint
        else:
            high = midpoint - 1
    return _truncate(original, low, marker)


def prepare_l3_prompt(
    settings: LLMPromptBudgetConfig,
    *,
    prompt_session: str,
    action_history: list[dict[str, object]],
    prompt_history: list[dict[str, object]] | None,
    a_next: dict[str, str],
    reason: str,
    skills_text: str,
    hints_text: str,
    script_analysis_text: str,
    skip_l3_hints: str,
    path_context: str,
) -> PreparedL3Prompt:
    turns, window_omitted = _visible_turns(prompt_history, settings.prompt_history_max_turns)
    turn_chars = settings.prompt_turn_max_chars
    lines, truncated = _history_lines(turns, turn_chars, turn_chars, len(turns))
    window_notice = _history_window_omission(window_omitted) if window_omitted else ""
    window_prefix = f"{window_notice}\n" if window_notice else ""
    needs_authorization = truncated or bool(window_omitted)
    max_items = settings.history_max_items
    initial_detail_chars = settings.action_detail_max_chars
    detail_chars = initial_detail_chars
    script_max_chars = settings.script_analysis_max_chars
    values = {
        "prompt_session": _truncate(prompt_session, settings.prompt_session_max_chars, _SESSION_SIZE_MARKER),
        "action_history": format_action_history(action_history, max_items, detail_chars),
        "prompt_history_text": window_prefix + "\n".join(lines) if lines else window_notice or _NO_PROMPT_HISTORY,
        "history_authorization": _HISTORY_AUTHORIZATION if needs_authorization else "",
        "a_next": a_next,
        "reason": reason,
        "skills_text": skills_text,
        "hints_text": hints_text,
        "script_analysis_text": _truncate(script_analysis_text, script_max_chars, _SCRIPT_SIZE_MARKER),
        "skip_l3_hints": skip_l3_hints,
        "path_context": path_context,
    }

    def render(**overrides: str | dict[str, str]) -> str:
        return get_security_judge_prompt(**(values | overrides))

    budget = settings.max_prompt_tokens
    token_limit = budget * 100 // 115 if settings.mode == "hard" else budget
    prompt = render()
    if budget == 0 or estimate_tokens(prompt) <= token_limit:
        return PreparedL3Prompt(prompt, "initial")

    omission_summary = ""

    def finish() -> PreparedL3Prompt:
        required_session = _truncate(prompt_session, settings.prompt_session_min_chars, _SESSION_BUDGET_MARKER)
        floor = render(
            prompt_session=min(values["prompt_session"], required_session, key=len),
            action_history="",
            prompt_history_text=window_prefix + omission_summary if omission_summary else window_notice,
            a_next={"action_type": "", "action_detail": ""},
            reason="",
            skills_text="",
            script_analysis_text="",
            path_context="",
        )
        floor_estimate = estimate_tokens(floor)
        code = (
            "l3_budget_floor_exceeds" if settings.mode == "hard" and floor_estimate > token_limit
            else "l3_budget_unreachable"
        )
        return PreparedL3Prompt(prompt, "floor", code, floor_estimate)

    if settings.mode == "hard" and estimate_tokens(hints_text) > token_limit:
        return finish()

    for item_cap, detail_cap in ((10, 250), (5, 100), (2, 100)):
        max_items = min(max_items, item_cap) if max_items else item_cap
        detail_chars = min(detail_chars, detail_cap) if detail_chars else detail_cap
        history = format_action_history(action_history, max_items, initial_detail_chars, budget_chars=detail_chars)
        if len(history) < len(values["action_history"]):
            values["action_history"] = history
            prompt = render()
            if estimate_tokens(prompt) <= token_limit:
                return PreparedL3Prompt(prompt, "action_history")

    minimum_turn_chars = settings.prompt_turn_min_chars
    old_chars = turn_chars
    for step in (300, 200, minimum_turn_chars):
        next_chars = min(old_chars, max(step, minimum_turn_chars))
        if next_chars == old_chars:
            continue
        old_chars = next_chars
        stage_lines, _ = _history_lines(turns, turn_chars, old_chars, settings.prompt_recent_turns_full)
        shorter_lines = [
            after if len(after) < len(before) else before
            for before, after in zip(lines, stage_lines, strict=True)
        ]
        if shorter_lines != lines:
            history = window_prefix + "\n".join(shorter_lines)
            candidate = render(prompt_history_text=history, history_authorization=_HISTORY_AUTHORIZATION)
            if len(candidate) >= len(prompt):
                continue
            lines = shorter_lines
            values["prompt_history_text"] = history
            values["history_authorization"] = _HISTORY_AUTHORIZATION
            prompt = candidate
            if estimate_tokens(prompt) <= token_limit:
                return PreparedL3Prompt(prompt, "historical_intent_text")

    before_omission = None
    omitted = _oldest_turns_to_omit(turns, lines, render, token_limit, window_prefix) if lines else 0
    if omitted:
        before_omission = {
            "prompt_history_text": values["prompt_history_text"],
            "history_authorization": values["history_authorization"],
        }
        omitted_intents = sum(bool(turn.text) for turn in turns[:omitted])
        omission_summary = _history_omission(omitted_intents, omitted - omitted_intents)
        values["prompt_history_text"] = window_prefix + "\n".join([omission_summary, *lines[omitted:]])
        if omitted_intents:
            values["history_authorization"] = _HISTORY_AUTHORIZATION
        prompt = render()
        if estimate_tokens(prompt) <= token_limit:
            return PreparedL3Prompt(prompt, "historical_intent_turns")

    # floor(len / 2.5) + 1 <= token_limit, solved for the rendered character count.
    char_limit = (token_limit * 5 - 1) // 2
    detail = a_next.get("action_detail", "")
    trimmed_detail = _truncate_to_room(
        detail, detail, 200, len(detail), char_limit - len(prompt) + len(detail), _DETAIL_MARKER,
    )
    if trimmed_detail != detail:
        values["a_next"] = {**a_next, "action_detail": trimmed_detail}
        prompt = render()
        if estimate_tokens(prompt) <= token_limit:
            return PreparedL3Prompt(prompt, "current_action")

    for field, source, cap, marker in (
        ("script_analysis_text", script_analysis_text, min(2000, script_max_chars), _SCRIPT_BUDGET_MARKER),
        ("script_analysis_text", script_analysis_text, min(1000, script_max_chars), _SCRIPT_BUDGET_MARKER),
        ("skills_text", skills_text, 2000, _DETAIL_MARKER),
        ("path_context", path_context, 2000, _DETAIL_MARKER),
        ("reason", reason, 1000, _DETAIL_MARKER),
    ):
        text = _truncate(source, cap, marker)
        if len(text) < len(values[field]):
            values[field] = text
            prompt = render()
            if estimate_tokens(prompt) <= token_limit:
                return PreparedL3Prompt(prompt, field)

    shown_session = values["prompt_session"]
    trimmed_session = _truncate_to_room(
        prompt_session, shown_session, settings.prompt_session_min_chars, settings.prompt_session_max_chars,
        char_limit - len(prompt) + len(shown_session), _SESSION_BUDGET_MARKER,
    )
    if trimmed_session != shown_session:
        values["prompt_session"] = trimmed_session
        prompt = render()
        if estimate_tokens(prompt) <= token_limit:
            return PreparedL3Prompt(prompt, "current_request")

    if settings.mode == "soft" and before_omission is not None:
        restored = render(**before_omission)
        if estimate_tokens(restored) <= estimate_tokens(prompt):
            values.update(before_omission)
            omission_summary = ""
            prompt = restored

    return finish()
