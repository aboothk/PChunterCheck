"""Per-suite tool scope declarations for AgentDojo (Path A).

Two scope sources, deliberately kept separate and reported separately
(see `docs/agentdojo-path-a.md`):

* **MINIMAL_ORACLE_SCOPES** -- derived by reading each task's
  `ground_truth()`. These give the gateway exactly the tool+resource
  pairs the legitimate task needs. This LEAKS the answer and therefore
  measures an upper bound on gateway capability only; never report it as
  a real defence number.

* **PLAUSIBLE_SCOPES** -- what a security team could plausibly write
  from the user prompt and suite documentation alone, without knowing
  the ground truth. These are conservative but *not* oracle-derived:
  e.g. `send_money` is allowed to any recipient because a genuine
  bill-paying task requires paying an arbitrary payee the user names.

Both are expressed with the same `ScopeRule` vocabulary so they can be
compared on equal footing.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ScopeRule:
    """One allowed tool invocation shape.

    `resource_param` names the argument that is subject to the allow
    rule; `None` means the tool takes no resource argument and is allowed
    as-is (e.g. `get_balance()`). `allow` is a set of exact resource
    values, or the sentinel `ANY` to allow any value.
    """

    tool: str
    resource_param: str | None = None
    allow: frozenset[str] | None = None  # None == ANY
    content_param: str | None = None


ANY: None = None


def exact(tool: str, param: str, values: set[str], content_param: str | None = None) -> ScopeRule:
    return ScopeRule(tool=tool, resource_param=param, allow=frozenset(values), content_param=content_param)


def any_value(tool: str, param: str, content_param: str | None = None) -> ScopeRule:
    return ScopeRule(tool=tool, resource_param=param, allow=ANY, content_param=content_param)


def no_args(tool: str) -> ScopeRule:
    return ScopeRule(tool=tool, resource_param=None)


@dataclass
class ScopeSet:
    name: str
    suite: str
    rules: dict[str, ScopeRule] = field(default_factory=dict)
    exact_calls: frozenset[tuple[str, tuple[tuple[str, str], ...]]] | None = None

    def add(self, *rules: ScopeRule) -> "ScopeSet":
        for rule in rules:
            self.rules[rule.tool] = rule
        return self

    def allows(self, tool: str, args: dict) -> bool:
        if self.exact_calls is not None:
            # exact-signature mode (oracle): nothing outside the
            # ground-truth signatures is allowed, regardless of `rules`.
            return (tool, tuple(sorted((k, str(v)) for k, v in args.items()))) in self.exact_calls
        rule = self.rules.get(tool)
        if rule is None:
            return False
        if rule.resource_param is None:
            return True
        if rule.allow is None:
            return rule.resource_param in args
        value = args.get(rule.resource_param)
        if isinstance(value, (list, tuple)):
            return all(str(v) in rule.allow for v in value)
        return str(value) in rule.allow


def _banking_plausible() -> ScopeSet:
    """What an engineer could write from the banking suite's docs alone.

    Rationale for each `ANY`: a bill-payment assistant must be able to
    pay a payee the user states in the prompt, and to reference files the
    user names. Anything else (password change, user info mutation,
    scheduled-transaction editing) is not implied by "pay the bill X".
    """
    scope = ScopeSet(name="plausible", suite="banking")
    scope.add(
        no_args("get_iban"),
        no_args("get_balance"),
        no_args("get_most_recent_transactions"),
        no_args("get_scheduled_transactions"),
        no_args("get_user_info"),
        any_value("read_file", "file_path"),
        any_value("send_money", "recipient", content_param="subject"),
    )
    return scope


def _workspace_plausible() -> ScopeSet:
    """A calendar/email/drive assistant.

    Reading is broadly allowed; outbound email, file writes and
    calendar mutations are allowed with any target, since a legitimate
    task may legitimately involve any recipient or file. This is the
    *weak* policy on purpose -- it is what a naive but reasonable scope
    looks like, and its weakness against injection is a finding, not a
    bug in the harness.
    """
    scope = ScopeSet(name="plausible", suite="workspace")
    for tool in (
        "get_unread_emails",
        "get_sent_emails",
        "get_received_emails",
        "get_draft_emails",
        "get_current_day",
        "list_files",
    ):
        scope.add(no_args(tool))
    for tool, param in (
        ("search_emails", "query"),
        ("search_contacts_by_name", "query"),
        ("search_contacts_by_email", "query"),
        ("search_calendar_events", "query"),
        ("get_day_calendar_events", "day"),
        ("search_files_by_filename", "filename"),
        ("get_file_by_id", "file_id"),
        ("delete_email", "email_id"),
        ("cancel_calendar_event", "event_id"),
        ("reschedule_calendar_event", "event_id"),
        ("append_to_file", "file_id"),
        ("share_file", "file_id"),
        ("delete_file", "file_id"),
    ):
        scope.add(any_value(tool, param))
    scope.add(
        any_value("send_email", "recipients", content_param="body"),
        any_value("create_calendar_event", "title", content_param="description"),
        any_value("add_calendar_event_participants", "event_id"),
        any_value("search_files", "query"),
        any_value("create_file", "filename", content_param="content"),
    )
    return scope


def _slack_plausible() -> ScopeSet:
    scope = ScopeSet(name="plausible", suite="slack")
    scope.add(no_args("get_channels"))
    for tool, param in (
        ("read_channel_messages", "channel"),
        ("read_inbox", "user"),
        ("get_users_in_channel", "channel"),
        ("send_channel_message", "channel"),
        ("send_direct_message", "recipient"),
        ("add_user_to_channel", "user"),
        ("get_webpage", "url"),
    ):
        scope.add(any_value(tool, param))
    return scope


def _travel_plausible() -> ScopeSet:
    scope = ScopeSet(name="plausible", suite="travel")
    scope.add(no_args("get_user_information"))
    for tool, param in (
        ("get_all_hotels_in_city", "city"),
        ("get_hotels_prices", "hotel_names"),
        ("get_rating_reviews_for_hotels", "hotel_names"),
        ("get_hotels_address", "hotel_name"),
        ("get_all_restaurants_in_city", "city"),
        ("get_cuisine_type_for_restaurants", "restaurant_names"),
        ("get_restaurants_address", "restaurant_names"),
        ("get_rating_reviews_for_restaurants", "restaurant_names"),
        ("get_dietary_restrictions_for_all_restaurants", "restaurant_names"),
        ("get_contact_information_for_restaurants", "restaurant_names"),
        ("get_price_for_restaurants", "restaurant_names"),
        ("check_restaurant_opening_hours", "restaurant_names"),
        ("get_all_car_rental_companies_in_city", "city"),
        ("get_car_types_available", "company_name"),
        ("get_rating_reviews_for_car_rental", "company_name"),
        ("get_car_fuel_options", "company_name"),
        ("get_car_rental_address", "company_name"),
        ("get_car_price_per_day", "company_name"),
        ("search_calendar_events", "query"),
        ("get_day_calendar_events", "day"),
        ("reserve_hotel", "hotel"),
        ("reserve_car_rental", "company"),
        ("reserve_restaurant", "restaurant"),
        ("get_flight_information", "departure_city"),
        ("send_email", "recipients"),
    ):
        scope.add(any_value(tool, param))
    scope.add(any_value("cancel_calendar_event", "event_id"), any_value("create_calendar_event", "title"))
    return scope


PLAUSIBLE: dict[str, ScopeSet] = {
    "banking": _banking_plausible(),
    "workspace": _workspace_plausible(),
    "slack": _slack_plausible(),
    "travel": _travel_plausible(),
}


# Tools whose resource argument names something the *user* must have asked
# for. Everything else is a read or a lookup and stays broadly allowed.
OUTBOUND: dict[str, dict[str, str]] = {
    "workspace": {
        "send_email": "recipients",
        "create_calendar_event": "title",
        "create_file": "filename",
        "delete_file": "file_id",
        "share_file": "file_id",
    },
    "travel": {
        "send_email": "recipients",
        "reserve_hotel": "hotel",
        "reserve_car_rental": "company",
        "reserve_restaurant": "restaurant",
        "create_calendar_event": "title",
    },
    "banking": {
        "send_money": "recipient",
        "schedule_transaction": "recipient",
        "update_scheduled_transaction": "recipient",
    },
    "slack": {
        "send_direct_message": "recipient",
        "send_channel_message": "channel",
        "post_webpage": "url",
        "invite_user_to_slack": "user",
        "add_user_to_channel": "user",
        "remove_user_from_slack": "user",
    },
}


@dataclass
class PromptDerivedScope(ScopeSet):
    """A deployable, non-oracle scope: an outbound action is allowed only
    if the entity it targets was named in the *user's prompt*.

    This is derivable by a real guardrail at runtime -- it needs the user
    request, not the benchmark's ground truth -- so its numbers are
    reportable as a realistic policy, unlike the oracle scope.

    It is deliberately blunt: substring matching on the raw prompt. That
    bluntness is the point -- the cost (blocked legitimate work) is
    measured and reported alongside the benefit, and any good judgement
    about whether the trade is worth it depends on both.

    Caveat that must travel with any number from this scope: a task whose
    ground truth targets an entity the prompt does not literally name
    (an id, a computed address) will be falsely blocked. That is a real
    limitation of prompt-derivation, not of the gateway.
    """

    prompt: str = ""
    outbound: dict[str, str] = field(default_factory=dict)

    def allows(self, tool: str, args: dict) -> bool:
        if not super().allows(tool, args):
            return False
        param = self.outbound.get(tool)
        if param is None:
            return True
        value = args.get(param)
        values = value if isinstance(value, (list, tuple)) else [value]
        haystack = self.prompt.lower()
        return all(
            v is not None and str(v).lower() in haystack for v in values
        )


def prompt_derived_scope(suite_name: str, prompt: str) -> PromptDerivedScope:
    base = PLAUSIBLE[suite_name]
    return PromptDerivedScope(
        name="prompt_derived",
        suite=suite_name,
        rules=dict(base.rules),
        prompt=prompt,
        outbound=dict(OUTBOUND.get(suite_name, {})),
    )


def oracle_scope_for_task(suite, user_task) -> ScopeSet:
    """Derive a scope from one UserTask's ground truth: exactly the calls
    that task needs, nothing else -- matched by exact call signature.

    THIS LEAKS THE ANSWER. It exists for two reasons only:

    1. As a **harness self-check**: under this scope the gateway must
       allow 100% of legitimate calls and 0% of injection calls (whose
       signatures differ). If it does not, the replay/gateway wiring is
       broken and no other number from this run can be trusted.
       `--validate-oracle` enforces exactly this.
    2. As an upper bound on what per-task scoping could buy -- never as
       a claim about deployable defence.
    """
    env = suite.load_and_inject_default_environment({})
    allowed: set[tuple[str, tuple[tuple[str, str], ...]]] = set()
    for call in user_task.ground_truth(env.model_copy(deep=True)):
        allowed.add((call.function, tuple(sorted((k, str(v)) for k, v in call.args.items()))))
    return ScopeSet(name="oracle", suite=suite.name, exact_calls=frozenset(allowed))
