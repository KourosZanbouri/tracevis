"""Graphing backend abstraction (GitHub issue #64).

The rendering pipeline is split into two layers:

1. **Data model** — a ``networkx.MultiDiGraph`` with node/edge attributes
   (label, color, shape, title, ...). This is built once by ``utils.vis.vis()``
   and is backend-agnostic.

2. **Renderer** — a concrete class that serialises the data model into an
   HTML file using a specific JS library. ``VisJsRenderer`` wraps the
   existing pyvis/vis.js path; ``PlotlyRenderer`` is a new backend that
   emits Plotly.js HTML.

Both renderers consume the same data model, so DPI/CGNAT/forgery colours,
tooltips, and edge annotations carry over automatically.
"""

import json
import os
from collections import namedtuple

RenderResult = namedtuple("RenderResult", ["html", "graph_path"])

REVERSE_PATH_COLOR = "#FFA500"
HIGHLIGHT_COLOR = "#ff9500"

# A vendored Plotly bundle, if the operator dropped one in. Plotly.js is
# ~3.5 MB, so it is not committed to the repository; when it is absent and
# --attach was requested we say so rather than silently emitting a page that
# needs a CDN the measured network is likely to be blocking.
PLOTLY_LOCAL_BUNDLE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "lib", "plotly", "plotly.min.js")
PLOTLY_CDN = "https://cdn.plot.ly/plotly-2.35.2.min.js"


def _reverse_path_edges(graph, reverse_path, reverse_path_ips):
    """Return the set of edge keys ``(u, v, k)`` that are reverse-path legs.

    An edge qualifies when the node it points at is in the VP-convergence set.
    Node labels and the convergence set are both normalised through
    ``resolve_or_ip`` by ``utils.vis``, so they compare directly.
    """
    if not reverse_path or not reverse_path_ips:
        return set()
    marked = set()
    for u, v, k in graph.edges(keys=True):
        if graph.nodes[v].get("label", "") in reverse_path_ips:
            marked.add((u, v, k))
    return marked


class Renderer:
    """Base class for graph renderers.

    Subclasses implement :meth:`render`, which receives the
    ``networkx.MultiDiGraph`` and returns the rendered HTML string.
    """

    def render(self, graph, graph_name, **kwargs):
        raise NotImplementedError


class VisJsRenderer(Renderer):
    """Render via pyvis → vis.js (the original backend)."""

    def render(self, graph, graph_name, attach_jscss=False, phase_overlay=False,
               highlight_selected=False, reverse_path=False, reverse_path_ips=None,
               **kwargs):
        import pyvis._version
        from pyvis.network import Network

        from utils.vis import (
            MAIN_TEMPLATE_PATH,
            OFFLINE_TEMPLATE_PATH,
            _inject_edge_highlight,
            _inject_phase_overlay,
            _inject_reverse_path_legend,
        )

        # GitHub issue #44: mark edges whose destination node is in the
        # VP-convergence set as reverse-path legs (dashed, amber).
        #
        # This must happen BEFORE from_nx(). pyvis copies the networkx graph
        # into its own node/edge lists at that point; styling applied to the
        # networkx graph afterwards never reached the rendered page, so the
        # flag drew its legend and marked nothing. The styling goes onto a
        # copy so the caller's graph is not mutated as a side effect.
        marked = _reverse_path_edges(graph, reverse_path, reverse_path_ips)
        if marked:
            graph = graph.copy()
            for u, v, k in marked:
                # vis.js spells this "dashes" (bool or a dash-pattern array).
                # "dash" is not a vis.js edge property and was ignored.
                graph[u][v][k]["dashes"] = True
                graph[u][v][k]["color"] = REVERSE_PATH_COLOR

        net_vis = Network("1500px", "1500px",
                          directed=True, bgcolor="#eeeeee")
        if pyvis._version.__version__ > '0.1.9':
            net_vis.from_nx(graph, show_edge_weights=False)
        else:
            net_vis.from_nx(graph)
        net_vis.set_edge_smooth('dynamic')
        if attach_jscss:
            net_vis.set_template(OFFLINE_TEMPLATE_PATH)
        else:
            net_vis.set_template(MAIN_TEMPLATE_PATH)

        graph_name = graph_name.removesuffix(".json")
        graph_path = graph_name + ".html"
        html_content = net_vis.generate_html()
        if phase_overlay:
            html_content = _inject_phase_overlay(html_content)
        if highlight_selected:
            html_content = _inject_edge_highlight(html_content)
        # Only label the graph when at least one edge actually carries the
        # marking. A legend explaining amber dashed edges on a page that has
        # none is worse than no legend at all.
        if reverse_path and reverse_path_ips:
            html_content = _inject_reverse_path_legend(html_content)
        return RenderResult(html=html_content, graph_path=graph_path)


class PlotlyRenderer(Renderer):
    """Render via Plotly.js.

    Plotly needs static 2-D coordinates (vis.js runs a physics simulation
    client-side), so positions are computed here with a layered layout.
    Node colours, edge colours, and tooltip text are preserved from the
    networkx attributes.
    """

    @staticmethod
    def _layered_layout(graph):
        """Position nodes by hop distance from the source(s).

        A traceroute graph is a shallow DAG rooted at one node per vantage
        point, so laying it out in columns by BFS depth reproduces the
        left-to-right path shape a reader expects. The previous circular
        layout put hop 1 next to hop 12 and ran every edge across the middle
        of the plot, which is unreadable past a handful of nodes — this
        repository's own multi-VP capture has 24 nodes and 84 edges.
        """
        nodes = list(graph.nodes())
        if not nodes:
            return {}
        if len(nodes) == 1:
            return {nodes[0]: (0.0, 0.0)}

        roots = [n for n in nodes if graph.in_degree(n) == 0]
        if not roots:
            # Fully cyclic (or every node reachable); fall back to node order.
            roots = [nodes[0]]

        depth = {n: 0 for n in roots}
        frontier = list(roots)
        while frontier:
            nxt = []
            for node in frontier:
                for successor in graph.successors(node):
                    if successor not in depth:
                        depth[successor] = depth[node] + 1
                        nxt.append(successor)
            frontier = nxt
        # Anything unreachable from a root goes in a trailing column.
        max_depth = max(depth.values()) if depth else 0
        for node in nodes:
            depth.setdefault(node, max_depth + 1)

        columns = {}
        for node in nodes:
            columns.setdefault(depth[node], []).append(node)

        pos = {}
        widest = max(len(c) for c in columns.values())
        for d, column in columns.items():
            for row, node in enumerate(column):
                # Centre each column vertically against the widest one.
                offset = (widest - len(column)) / 2.0
                pos[node] = (float(d), float(row + offset))
        return pos

    def render(self, graph, graph_name, attach_jscss=False, phase_overlay=False,
               highlight_selected=False, reverse_path=False, reverse_path_ips=None,
               **kwargs):
        from utils.vis import (
            _inject_phase_overlay,
            _inject_reverse_path_legend,
        )

        pos = self._layered_layout(graph)
        marked = _reverse_path_edges(graph, reverse_path, reverse_path_ips)

        node_index = {}
        nodes_x, nodes_y = [], []
        node_text, node_color, node_shape, node_titles = [], [], [], []
        for node_id in graph.nodes():
            node_index[node_id] = len(nodes_x)
            x, y = pos[node_id]
            nodes_x.append(x)
            nodes_y.append(y)
            node_text.append(graph.nodes[node_id].get("label", ""))
            node_color.append(graph.nodes[node_id].get("color", "gray"))
            node_shape.append(graph.nodes[node_id].get("shape", "dot"))
            node_titles.append(graph.nodes[node_id].get("title", ""))

        edges = []
        for src, dst, key, edge_data in graph.edges(keys=True, data=True):
            x0, y0 = pos[src]
            x1, y1 = pos[dst]
            is_reverse = (src, dst, key) in marked
            edges.append({
                "from": node_index[src],
                "to": node_index[dst],
                "x0": x0, "y0": y0, "x1": x1, "y1": y1,
                "color": (REVERSE_PATH_COLOR if is_reverse
                          else edge_data.get("color", "gray")),
                "dashed": is_reverse,
                "title": edge_data.get("title", ""),
                "label": edge_data.get("label", ""),
            })

        html = self._build_html(
            nodes_x=nodes_x, nodes_y=nodes_y, node_text=node_text,
            node_color=node_color, node_shape=node_shape,
            node_titles=node_titles, edges=edges,
            highlight_selected=highlight_selected,
            attach_jscss=attach_jscss,
        )

        if phase_overlay:
            html = _inject_phase_overlay(html)
        if reverse_path and reverse_path_ips:
            html = _inject_reverse_path_legend(html)

        graph_name = graph_name.removesuffix(".json")
        graph_path = graph_name + ".html"
        return RenderResult(html=html, graph_path=graph_path)

    @staticmethod
    def _plotly_script_tag(attach_jscss):
        """Return the <script> tag that loads Plotly.js.

        With ``attach_jscss`` the caller has told us the measured network may
        not be able to reach a CDN — that flag is set automatically when
        tracevis detects a censored or down network. Inline a vendored bundle
        if one is present; otherwise say plainly that the page will need the
        CDN, instead of writing a file that silently renders blank.
        """
        if attach_jscss:
            try:
                with open(PLOTLY_LOCAL_BUNDLE, encoding="utf-8") as handle:
                    return "<script>" + handle.read() + "</script>"
            except OSError:
                print("· · · - · warning: --attach cannot be honoured by the "
                      "plotly renderer: no vendored bundle at "
                      + PLOTLY_LOCAL_BUNDLE)
                print("· · · - ·   the graph will load Plotly from "
                      + PLOTLY_CDN + " and stays blank without it.")
                print("· · · - ·   use --renderer visjs for a fully "
                      "self-contained page.")
        return '<script src="' + PLOTLY_CDN + '"></script>'

    def _build_html(self, nodes_x, nodes_y, node_text, node_color, node_shape,
                    node_titles, edges, highlight_selected, attach_jscss):
        """Generate the Plotly HTML document."""
        data = {
            "nodes_x": nodes_x, "nodes_y": nodes_y, "node_text": node_text,
            "node_color": node_color, "node_shape": node_shape,
            "node_titles": node_titles, "edges": edges,
            "highlight_color": HIGHLIGHT_COLOR,
            "highlight_enabled": bool(highlight_selected),
        }
        shape_marker_map = {
            'diamond': 'diamond', 'square': 'square', 'hexagon': 'hexagram',
            'star': 'star', 'dot': 'circle', 'box': 'square',
            'circle': 'circle', 'triangle': 'triangle-up',
            'triangleDown': 'triangle-down',
        }
        return (
            "<!DOCTYPE html>\n<html>\n<head>\n<meta charset=\"utf-8\"/>\n"
            + self._plotly_script_tag(attach_jscss)
            + "\n<style>\nbody { margin: 0; font-family: sans-serif; }\n"
              "#graph { width: 100%; height: 100vh; }\n</style>\n"
              "</head>\n<body>\n<div id=\"graph\"></div>\n<script>\n"
            + "var GRAPH = " + json.dumps(data) + ";\n"
            + "var SHAPE_MARKERS = " + json.dumps(shape_marker_map) + ";\n"
            + PLOTLY_DRAW_JS
            + "\n</script>\n</body>\n</html>"
        )


# Kept out of the f-string/format machinery on purpose: this is plain
# JavaScript with its own braces, and embedding it in a Python format string
# is what left literal `{{` / `}}` in the previously emitted page.
PLOTLY_DRAW_JS = r"""
(function () {
    var gd = document.getElementById('graph');
    var nodes_x = GRAPH.nodes_x, nodes_y = GRAPH.nodes_y;
    var edges = GRAPH.edges;
    var traces = [];

    // --- edges -----------------------------------------------------------
    // One Plotly trace per edge does not scale: a 24-node capture produces 84
    // traces and Plotly re-lays-out on every one. Group the segments by
    // (colour, dashed) instead and separate them with nulls, so the number of
    // traces is the number of distinct colours rather than the edge count.
    var groups = {};
    edges.forEach(function (e) {
        var key = e.color + '|' + (e.dashed ? 'dash' : 'solid');
        if (!groups[key]) {
            groups[key] = {x: [], y: [], color: e.color, dashed: e.dashed};
        }
        groups[key].x.push(e.x0, e.x1, null);
        groups[key].y.push(e.y0, e.y1, null);
    });
    Object.keys(groups).forEach(function (key) {
        var g = groups[key];
        traces.push({
            x: g.x, y: g.y, mode: 'lines', type: 'scatter',
            line: {color: g.color, width: 2, dash: g.dashed ? 'dash' : 'solid'},
            hoverinfo: 'skip', showlegend: false
        });
    });

    // A marker at each edge midpoint carries that edge's tooltip. Hover text
    // has to live on a per-point array; the previous code put a single joined
    // string in `hovertemplate`, which Plotly applies to every point in the
    // trace, so every element showed every other element's tooltip.
    var midX = [], midY = [], midText = [], midIds = [];
    edges.forEach(function (e, i) {
        midX.push((e.x0 + e.x1) / 2);
        midY.push((e.y0 + e.y1) / 2);
        midText.push(e.title || e.label || '');
        midIds.push(i);
    });
    var edgeHoverTrace = traces.length;
    traces.push({
        x: midX, y: midY, mode: 'markers', type: 'scatter',
        marker: {size: 10, color: 'rgba(0,0,0,0)'},
        text: midText, customdata: midIds,
        hovertemplate: '%{text}<extra></extra>',
        showlegend: false
    });

    // --- nodes -----------------------------------------------------------
    var shapes = {};
    for (var i = 0; i < nodes_x.length; i++) {
        var marker = SHAPE_MARKERS[GRAPH.node_shape[i] || 'dot'] || 'circle';
        if (!shapes[marker]) {
            shapes[marker] = {x: [], y: [], labels: [], colors: [], titles: []};
        }
        shapes[marker].x.push(nodes_x[i]);
        shapes[marker].y.push(nodes_y[i]);
        shapes[marker].labels.push(GRAPH.node_text[i]);
        shapes[marker].colors.push(GRAPH.node_color[i]);
        shapes[marker].titles.push(GRAPH.node_titles[i]);
    }
    Object.keys(shapes).forEach(function (marker) {
        var d = shapes[marker];
        traces.push({
            x: d.x, y: d.y, mode: 'markers+text', type: 'scatter',
            marker: {symbol: marker, size: 14, color: d.colors,
                     line: {color: '#333', width: 1}},
            text: d.labels, textposition: 'top center',
            customdata: d.titles,
            hovertemplate: '%{customdata}<extra></extra>',
            showlegend: false
        });
    });

    var layout = {
        margin: {t: 20, b: 20, l: 20, r: 20},
        plot_bgcolor: '#eeeeee', paper_bgcolor: '#eeeeee',
        showlegend: false, dragmode: 'pan', hovermode: 'closest',
        xaxis: {visible: false, showgrid: false, zeroline: false},
        yaxis: {visible: false, showgrid: false, zeroline: false}
    };
    var config = {displayModeBar: true, displaylogo: false, responsive: true};

    Plotly.newPlot('graph', traces, layout, config).then(function () {
        if (!GRAPH.highlight_enabled) { return; }
        // Plotly events are emitted on the graph div by Plotly's own emitter
        // via gd.on(...). addEventListener('plotly_click', ...) never fires,
        // which is why the previous handler was inert.
        var highlightTrace = null;
        gd.on('plotly_click', function (ev) {
            var point = ev && ev.points && ev.points[0];
            if (!point || point.curveNumber !== edgeHoverTrace) {
                return clearHighlight();
            }
            var start = point.customdata;
            var seen = {}, hx = [], hy = [];
            var current = start;
            // Visited set: a routing loop in the traced path, or the parallel
            // edges a multi-VP graph creates, otherwise spin here forever.
            while (current !== undefined && !seen[current]) {
                seen[current] = true;
                var e = edges[current];
                hx.push(e.x0, e.x1, null);
                hy.push(e.y0, e.y1, null);
                current = undefined;
                for (var j = 0; j < edges.length; j++) {
                    if (edges[j].to === e.from && !seen[j]) { current = j; break; }
                }
            }
            clearHighlight();
            Plotly.addTraces(gd, {
                x: hx, y: hy, mode: 'lines', type: 'scatter',
                line: {color: GRAPH.highlight_color, width: 5},
                hoverinfo: 'skip', showlegend: false
            }).then(function () { highlightTrace = gd.data.length - 1; });
        });
        function clearHighlight() {
            if (highlightTrace !== null) {
                Plotly.deleteTraces(gd, highlightTrace);
                highlightTrace = null;
            }
        }
    });
})();
"""


RENDERERS = {
    "visjs": VisJsRenderer(),
    "plotly": PlotlyRenderer(),
}


def get_renderer(name):
    """Return a renderer by name, defaulting to vis.js."""
    return RENDERERS.get(name, RENDERERS["visjs"])
