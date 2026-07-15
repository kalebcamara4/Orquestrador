from bb_orchestrator.triage_selection import (
    ROUTE_SELECTION_POLICY,
    RouteCategory,
    classify_triage_path,
    select_triage_paths,
)


def test_route_priority_policy_name_is_versioned() -> None:
    assert ROUTE_SELECTION_POLICY == "route-priority-v1"


def test_classification_uses_lowercase_segment_boundaries() -> None:
    assert classify_triage_path("/API/v1") is RouteCategory.APPLICATION_LIKELY
    assert classify_triage_path("/shop/MEU-PEDIDO/details") is (RouteCategory.APPLICATION_LIKELY)
    assert classify_triage_path("/capivara") is RouteCategory.DYNAMIC_LIKELY
    assert classify_triage_path("/administrator") is RouteCategory.DYNAMIC_LIKELY
    assert classify_triage_path("/profiles-preview") is RouteCategory.DYNAMIC_LIKELY


def test_classification_recognizes_routes_dynamic_files_javascript_and_static_files() -> None:
    assert classify_triage_path("/") is RouteCategory.ROOT
    assert classify_triage_path("/openapi.json") is RouteCategory.API_OR_DYNAMIC_FILE
    assert classify_triage_path("/legacy/index.PHP") is RouteCategory.API_OR_DYNAMIC_FILE
    assert classify_triage_path("/catalog/items") is RouteCategory.DYNAMIC_LIKELY
    assert classify_triage_path("/assets/application.js") is RouteCategory.JAVASCRIPT_REFERENCE
    assert classify_triage_path("/assets/application.min.js") is RouteCategory.STATIC_LIKELY
    assert classify_triage_path("/vendor/jquery.js") is RouteCategory.STATIC_LIKELY
    assert classify_triage_path("/app/onesignal/init.js") is RouteCategory.STATIC_LIKELY
    assert classify_triage_path("/sdks/OneSignalSDK.page.js") is RouteCategory.STATIC_LIKELY
    assert classify_triage_path("/api/assets/application.css") is RouteCategory.STATIC_LIKELY
    assert classify_triage_path("/manifest.json") is RouteCategory.STATIC_LIKELY
    assert classify_triage_path("/assets/app-manifest.123.json") is RouteCategory.STATIC_LIKELY


def test_selection_orders_categories_then_paths_lexicographically() -> None:
    paths = [
        "/assets/z.js",
        "/z-route",
        "/swagger.json",
        "/users/current",
        "/login",
        "/assets/a.js",
        "/a-route",
        "/",
        "/assets/site.css",
    ]

    selection = select_triage_paths(list(reversed(paths)))

    assert selection.paths == (
        "/",
        "/login",
        "/users/current",
        "/swagger.json",
        "/a-route",
        "/z-route",
        "/assets/a.js",
        "/assets/z.js",
    )
    assert selection.paths_omitted_by_policy == 1
    assert selection.paths_omitted_by_limit == 0


def test_dynamic_paths_win_javascript_and_javascript_is_limited_to_five() -> None:
    javascript = [f"/assets/script-{index}.js" for index in reversed(range(8))]
    selection = select_triage_paths([*javascript, "/catalog", "/checkout/start"])

    assert selection.paths == (
        "/checkout/start",
        "/catalog",
        *tuple(f"/assets/script-{index}.js" for index in range(5)),
    )
    assert selection.paths_included == 7
    assert selection.paths_omitted_by_policy == 3
    assert selection.paths_omitted_by_limit == 0


def test_javascript_is_not_included_when_higher_categories_fill_the_limit() -> None:
    dynamic_paths = [f"/route/{index:03d}" for index in range(50)]
    selection = select_triage_paths([*dynamic_paths, "/assets/application.js"])

    assert selection.paths == tuple(dynamic_paths)
    assert selection.paths_omitted_by_policy == 0
    assert selection.paths_omitted_by_limit == 1


def test_static_paths_are_not_used_to_fill_the_batch() -> None:
    static_paths = [f"/media/styles-{index:02d}.css" for index in range(40)]
    selection = select_triage_paths([*static_paths, "/cardapio", "/area-de-entrega"])

    assert selection.paths == ("/area-de-entrega", "/cardapio")
    assert selection.paths_total == 42
    assert selection.paths_included == 2
    assert selection.paths_omitted_by_policy == 40
    assert selection.paths_omitted_by_limit == 0


def test_limit_deduplication_order_and_reexecution_are_deterministic() -> None:
    dynamic_paths = [f"/route/{index:03d}" for index in range(60)]
    inputs = [
        *reversed(dynamic_paths),
        "/",
        "/route/000",
        "/media/site.css",
    ]

    first = select_triage_paths(inputs)
    second = select_triage_paths(list(reversed(inputs)))

    assert first == second
    assert first.paths == ("/", *tuple(dynamic_paths[:49]))
    assert first.paths_total == 62
    assert first.paths_included == 50
    assert first.paths_omitted_by_policy == 1
    assert first.paths_omitted_by_limit == 11
