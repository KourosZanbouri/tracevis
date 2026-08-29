"""GitHub issue #64: graphing backend abstraction tests."""
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
import unittest.mock
from contextlib import redirect_stdout
from itertools import pairwise

import networkx

import utils.renderer
import utils.vis
from test.test_vis import make_measurement
from utils.renderer import (
    RENDERERS,
    PlotlyRenderer,
    VisJsRenderer,
    get_renderer,
)


class RendererMixin:
    """Write a measurement list to a temp file, render it, return the HTML."""

    def render(self, measurements, renderer_name="visjs", **kwargs):
        directory = tempfile.mkdtemp()
        self.addCleanup(
            lambda: [os.remove(os.path.join(directory, n))
                     for n in os.listdir(directory)] and None
            or os.rmdir(directory))
        path = os.path.join(directory, "m.json")
        with open(path, "w") as handle:
            json.dump(measurements, handle)
        with redirect_stdout(io.StringIO()):
            utils.vis.vis(
                measurement_path=path, attach_jscss=False,
                edge_lable="none", renderer=renderer_name, **kwargs)
        with open(path.replace(".json", ".html"), errors="replace") as handle:
            return handle.read()


class TestRendererRegistry(unittest.TestCase):
    """Both backends must be registered and discoverable."""

    def test_visjs_registered(self):
        self.assertIn("visjs", RENDERERS)
        self.assertIsInstance(RENDERERS["visjs"], VisJsRenderer)

    def test_plotly_registered(self):
        self.assertIn("plotly", RENDERERS)
        self.assertIsInstance(RENDERERS["plotly"], PlotlyRenderer)

    def test_get_renderer_default(self):
        self.assertIs(get_renderer("nonexistent"), RENDERERS["visjs"])

    def test_get_renderer_plotly(self):
        self.assertIs(get_renderer("plotly"), RENDERERS["plotly"])


class TestVisJsRenderer(RendererMixin, unittest.TestCase):
    """The original backend must produce identical output when selected explicitly."""

    def test_visjs_output_contains_vis_network(self):
        page = self.render([make_measurement()], renderer_name="visjs")
        self.assertIn("vis.Network", page)

    def test_visjs_still_renders_cgnat(self):
        page = self.render([make_measurement(cgnat_hop=True)],
                           renderer_name="visjs")
        self.assertIn("teal", page)


class TestPlotlyRenderer(RendererMixin, unittest.TestCase):
    """The new Plotly backend must emit valid Plotly HTML."""

    def test_plotly_output_contains_plotly(self):
        page = self.render([make_measurement()], renderer_name="plotly")
        self.assertIn("cdn.plot.ly", page)
        self.assertIn("Plotly.newPlot", page)

    def test_plotly_contains_node_labels(self):
        page = self.render([make_measurement()], renderer_name="plotly")
        self.assertIn("192.168.1.1", page)
        self.assertIn("100.64.0.1", page)

    def test_plotly_contains_edge_titles(self):
        page = self.render([make_measurement()], renderer_name="plotly")
        # Edge tooltips should carry TTL info from the styled_tooltips output.
        self.assertIn("TTL:", page)

    def test_plotly_carries_cgnat_color(self):
        page = self.render([make_measurement(cgnat_hop=True)],
                           renderer_name="plotly")
        self.assertIn("teal", page)

    def test_plotly_supports_phase_overlay(self):
        page = self.render([make_measurement()], renderer_name="plotly",
                           phase_overlay=True)
        self.assertIn("phase-overlay", page)


# ---------------------------------------------------------------------------
# Regression tests for the renderer review (issues #2, #44, #64).
# ---------------------------------------------------------------------------


def _simple_graph(reverse_target="10.0.0.2"):
    """A two-node graph whose second node is the reverse-path convergence."""
    graph = networkx.MultiDiGraph()
    graph.add_node("a", label="10.0.0.1", color="red", shape="diamond",
                   title="source address")
    graph.add_node("b", label=reverse_target, color="blue", shape="dot",
                   title="Router")
    graph.add_edge("a", "b", label="1", color="blue", title="TTL: 1")
    return graph


class TestReversePathStylingReachesOutput(unittest.TestCase):
    """The styling was applied to the networkx graph *after* pyvis copied it.

    pyvis takes its own snapshot of nodes and edges inside from_nx(); mutating
    the networkx graph afterwards never reached the page. --reverse-path drew
    its legend and marked nothing.
    """

    def _rendered_edges(self, html):
        match = re.search(r"edges = new vis\.DataSet\((.*?)\);", html, re.DOTALL)
        return json.loads(match.group(1))

    def test_edge_is_amber_in_the_rendered_page(self):
        html = VisJsRenderer().render(
            _simple_graph(), "/tmp/x.json",
            reverse_path=True, reverse_path_ips={"10.0.0.2"}).html
        colors = [e.get("color") for e in self._rendered_edges(html)]
        self.assertIn(utils.renderer.REVERSE_PATH_COLOR, colors)

    def test_edge_is_dashed_using_the_visjs_property_name(self):
        """vis.js spells it `dashes`; `dash` was silently ignored."""
        html = VisJsRenderer().render(
            _simple_graph(), "/tmp/x.json",
            reverse_path=True, reverse_path_ips={"10.0.0.2"}).html
        edges = self._rendered_edges(html)
        marked = [e for e in edges
                  if e.get("color") == utils.renderer.REVERSE_PATH_COLOR]
        self.assertTrue(marked)
        for edge in marked:
            self.assertTrue(edge.get("dashes"))
            self.assertNotIn("dash", edge)

    def test_unmarked_edges_keep_their_own_colour(self):
        html = VisJsRenderer().render(
            _simple_graph(), "/tmp/x.json",
            reverse_path=True, reverse_path_ips={"192.0.2.99"}).html
        colors = [e.get("color") for e in self._rendered_edges(html)]
        self.assertEqual(colors, ["blue"])

    def test_renderer_does_not_mutate_the_caller_graph(self):
        graph = _simple_graph()
        VisJsRenderer().render(graph, "/tmp/x.json", reverse_path=True,
                               reverse_path_ips={"10.0.0.2"})
        self.assertEqual(graph["a"]["b"][0]["color"], "blue")
        self.assertNotIn("dashes", graph["a"]["b"][0])

    def test_no_legend_when_nothing_converged(self):
        html = VisJsRenderer().render(
            _simple_graph(), "/tmp/x.json",
            reverse_path=True, reverse_path_ips=set()).html
        self.assertNotIn("reverse-path-legend", html)

    def test_plotly_marks_reverse_path_edges(self):
        html = PlotlyRenderer().render(
            _simple_graph(), "/tmp/x.json",
            reverse_path=True, reverse_path_ips={"10.0.0.2"}).html
        self.assertIn(utils.renderer.REVERSE_PATH_COLOR, html)
        self.assertIn('"dashed": true', html)


class TestPlotlyTraceGrouping(unittest.TestCase):
    """One Plotly trace per edge does not scale."""

    def _graph(self, edge_count):
        graph = networkx.MultiDiGraph()
        for i in range(edge_count + 1):
            graph.add_node(f"n{i}", label=f"10.0.0.{i}", color="blue",
                           shape="dot", title=f"node {i}")
        for i in range(edge_count):
            graph.add_edge(f"n{i}", f"n{i + 1}", label="", color="blue",
                           title=f"TTL: {i}")
        return graph

    def test_edges_are_grouped_not_one_trace_each(self):
        html = PlotlyRenderer().render(self._graph(50), "/tmp/x.json").html
        payload = json.loads(re.search(r"var GRAPH = (.*);", html).group(1))
        self.assertEqual(len(payload["edges"]), 50)
        # All 50 share one colour, so they collapse into a single line trace
        # plus one hover-marker trace and the node traces.
        self.assertEqual(html.count("traces.push"), 3)

    def test_every_edge_keeps_its_own_hover_text(self):
        html = PlotlyRenderer().render(self._graph(5), "/tmp/x.json").html
        payload = json.loads(re.search(r"var GRAPH = (.*);", html).group(1))
        titles = [e["title"] for e in payload["edges"]]
        self.assertEqual(titles,
                         ["TTL: 0", "TTL: 1", "TTL: 2", "TTL: 3", "TTL: 4"])


class TestPlotlyHoverIsPerPoint(unittest.TestCase):
    """`hovertemplate: d.titles.join('<br>')` is one string for every point.

    Plotly applies a scalar hovertemplate to the whole trace, so every node
    showed the concatenation of all node tooltips.
    """

    def test_node_hover_reads_from_a_per_point_array(self):
        html = PlotlyRenderer().render(_simple_graph(), "/tmp/x.json").html
        self.assertIn("customdata: d.titles", html)
        self.assertIn("'%{customdata}<extra></extra>'", html)

    def test_no_joined_title_string(self):
        html = PlotlyRenderer().render(_simple_graph(), "/tmp/x.json").html
        self.assertNotIn("d.titles.join", html)

    def test_edge_hover_reads_from_a_per_point_array(self):
        html = PlotlyRenderer().render(_simple_graph(), "/tmp/x.json").html
        self.assertIn("'%{text}<extra></extra>'", html)


class TestPlotlyHighlightFlag(unittest.TestCase):
    """`self._injected_js('highlight_selected')` passed a truthy literal."""

    def test_highlight_enabled_flag_follows_the_argument(self):
        off = PlotlyRenderer().render(_simple_graph(), "/tmp/x.json",
                                      highlight_selected=False).html
        on = PlotlyRenderer().render(_simple_graph(), "/tmp/x.json",
                                     highlight_selected=True).html
        self.assertIn('"highlight_enabled": false', off)
        self.assertIn('"highlight_enabled": true', on)

    def test_uses_the_plotly_event_emitter_not_addeventlistener(self):
        """Plotly events fire through gd.on(); addEventListener never does."""
        html = PlotlyRenderer().render(_simple_graph(), "/tmp/x.json",
                                       highlight_selected=True).html
        self.assertIn("gd.on('plotly_click'", html)
        self.assertNotIn("gd.addEventListener('plotly_click'", html)

    def test_no_literal_double_braces_in_emitted_js(self):
        """The JS used to be built through a format string.

        Only the opening `{{` is checked: a closing `}}` occurs legitimately
        wherever a nested object literal ends (`line: {color: '#333'}}`),
        whereas `{{` in this source only ever came from an escaped brace that
        was never unescaped, because the block was returned from a plain
        string rather than an f-string.
        """
        html = PlotlyRenderer().render(_simple_graph(), "/tmp/x.json",
                                       highlight_selected=True).html
        script = html[html.index("var GRAPH ="):]
        self.assertNotIn("{{", script)

    def test_walk_has_a_visited_set(self):
        html = PlotlyRenderer().render(_simple_graph(), "/tmp/x.json",
                                       highlight_selected=True).html
        self.assertIn("seen[current]", html)


class TestPlotlyOfflineAssets(unittest.TestCase):
    """attach_jscss was accepted and ignored; the page always needed a CDN."""

    def test_warns_when_it_cannot_honour_attach(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            html = PlotlyRenderer().render(_simple_graph(), "/tmp/x.json",
                                           attach_jscss=True).html
        self.assertIn("cannot be honoured", buf.getvalue())
        self.assertIn("--renderer visjs", buf.getvalue())
        self.assertIn(utils.renderer.PLOTLY_CDN, html)

    def test_inlines_a_vendored_bundle_when_present(self):
        bundle = tempfile.mkdtemp()
        path = os.path.join(bundle, "plotly.min.js")
        with open(path, "w") as handle:
            handle.write("/* vendored plotly marker */")
        self.addCleanup(lambda: (os.remove(path), os.rmdir(bundle)))
        with unittest.mock.patch.object(utils.renderer,
                                        "PLOTLY_LOCAL_BUNDLE", path):
            html = PlotlyRenderer().render(_simple_graph(), "/tmp/x.json",
                                           attach_jscss=True).html
        self.assertIn("/* vendored plotly marker */", html)
        self.assertNotIn(utils.renderer.PLOTLY_CDN, html)

    def test_no_warning_without_attach(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            PlotlyRenderer().render(_simple_graph(), "/tmp/x.json")
        self.assertEqual(buf.getvalue(), "")


class TestPlotlyLayeredLayout(unittest.TestCase):
    """A circular layout runs every edge across the middle of the plot."""

    def test_hops_advance_left_to_right(self):
        graph = networkx.MultiDiGraph()
        chain = ["s", "a", "b", "c"]
        for node in chain:
            graph.add_node(node, label=node, color="blue", shape="dot",
                           title=node)
        for src, dst in pairwise(chain):
            graph.add_edge(src, dst, label="", color="blue", title="t")
        pos = PlotlyRenderer._layered_layout(graph)
        xs = [pos[n][0] for n in chain]
        self.assertTrue(all(a < b for a, b in pairwise(xs)))
        self.assertEqual(len(set(xs)), len(chain))

    def test_handles_a_cyclic_graph(self):
        graph = networkx.MultiDiGraph()
        for node in ("a", "b"):
            graph.add_node(node, label=node, color="blue", shape="dot",
                           title=node)
        graph.add_edge("a", "b", color="blue", label="", title="t")
        graph.add_edge("b", "a", color="blue", label="", title="t")
        pos = PlotlyRenderer._layered_layout(graph)
        self.assertEqual(set(pos), {"a", "b"})

    def test_handles_empty_and_single_node(self):
        self.assertEqual(PlotlyRenderer._layered_layout(networkx.MultiDiGraph()),
                         {})
        one = networkx.MultiDiGraph()
        one.add_node("a", label="a")
        self.assertEqual(PlotlyRenderer._layered_layout(one), {"a": (0.0, 0.0)})


class TestEmittedJavaScriptParses(unittest.TestCase):
    """Both backends' injected scripts must be syntactically valid JS."""

    @staticmethod
    def _node_available():
        return shutil.which("node") is not None

    def _check(self, source):
        if not self._node_available():
            self.skipTest("node is not installed")
        directory = tempfile.mkdtemp()
        path = os.path.join(directory, "check.js")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(source)
        self.addCleanup(lambda: (os.remove(path), os.rmdir(directory)))
        proc = subprocess.run(["node", "--check", path], check=False,
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_plotly_script_parses(self):
        html = PlotlyRenderer().render(_simple_graph(), "/tmp/x.json",
                                       highlight_selected=True).html
        body = re.search(r"<script>\n(var GRAPH.*?)\n</script>", html, re.DOTALL)
        self._check(body.group(1))

    def test_visjs_highlight_script_parses(self):
        source = utils.vis._inject_edge_highlight("<body></body>")
        script = re.search(r"<script>(.*?)</script>", source, re.DOTALL).group(1)
        self._check(
            "var network={on:function(){}},"
            "nodes={get:function(){},update:function(){}},"
            "edges={get:function(){},update:function(){}};\n" + script)


if __name__ == "__main__":
    unittest.main()
