"""Diagram 4: grey-box in detail (docs/images/greybox-detail.png)."""
from manim import Scene, VGroup, DOWN, UP, LEFT, RIGHT
from style import *

setup(23, 12.2)

TOP_Y, TOP_H = 1.9, 6.5
BAR_Y, BAR_H = -3.85, 1.9


class GreyboxDetail(Scene):
    def construct(self):
        add = self.add
        add(text("Grey-box: everything goes through the knowledge graph", 40, ACCENT, bold=True)
            .move_to([0, 5.65, 0]))

        # --- discovery
        dpanel = panel(8.9, TOP_H, "Discovery", "crawl, then managed scans", title_size=36).move_to([-6.5, TOP_Y - 0.3, 0])
        agent = node("Discovery agent", "crawls the app, logs in as each identity", w=7.4, h=1.45,
                     title_size=30, sub_size=22).move_to([-6.5, TOP_Y + 0.55 - 0.3, 0])
        scans = node("Managed scans", "Nuclei, feroxbuster, httpx, whatweb, TLS and header checks", w=7.4, h=1.55,
                     title_size=30, sub_size=22).move_to([-6.5, TOP_Y - 1.65 - 0.3, 0])
        add(dpanel, agent, scans, arrow(agent.get_bottom(), scans.get_top(), width=5, buff=0.05))

        # --- reactive exploitation
        rpanel = panel(11.8, TOP_H, "Reactive exploitation", "specialists spawned per verb", title_size=36).move_to([4.9, TOP_Y - 0.3, 0])
        sched = node("Scheduler", "plain Python, no LLM", w=3.5, h=1.9, fill="#3B2E7E", edge=PURPLE_EDGE,
                     title_size=32, sub_size=23).move_to([1.45, TOP_Y - 0.55 - 0.3, 0])
        group = panel(5.6, 5.0, "Parallel agents", None, title_color=TEXT, title_size=28,
                      fill="#222B58", edge=NODE_EDGE).move_to([7.55, TOP_Y - 0.55 - 0.3, 0])
        items = VGroup(*[node(a, b, w=5.0, h=0.82, title_size=22, sub_size=20)
                         for a, b in (("INVESTIGATE_LEAD", "follow one open lead"),
                                      ("PROBE_PARAMETERS", "test a batch of inputs"),
                                      ("TEST_ACCESS_MATRIX", "compare identities"),
                                      ("ATTEMPT_CHAIN", "combine findings"))])
        items.arrange(DOWN, buff=0.12).move_to(group.box.get_center() + DOWN * 0.4)
        add(rpanel, sched, group, items,
            arrow(sched.get_right(), group.box.get_left(), width=5, buff=0.05),
            text("verbs", 24, MUTED).move_to([3.95, TOP_Y - 0.1, 0]))

        # discovery -> exploitation
        add(arrow(dpanel.box.get_right(), rpanel.box.get_left(), ACCENT, width=8, tip=0.35, buff=0.05))

        # --- knowledge graph
        bar = node("Knowledge graph (SurrealDB)",
                   "endpoints, parameters, leads, test attempts, findings, identity access",
                   w=17.4, h=BAR_H, fill=LEDGER, edge=LEDGER_EDGE, title_size=34, sub_size=25).move_to([-2.2, BAR_Y, 0])
        top = BAR_Y + BAR_H / 2
        add(bar)
        specs = [(-6.5, "writes what it finds", "down"), (1.45, "reads on every tick", "up"),
                 (5.9, "write results back", "both")]
        for x, label, d in specs:
            y_hi = TOP_Y - 0.3 - TOP_H / 2 - 0.02
            if d == "down":
                a = arrow([x, y_hi, 0], [x, top + 0.02, 0], width=5, buff=0.0)
            elif d == "up":
                a = arrow([x, top + 0.02, 0], [x, y_hi, 0], width=5, buff=0.0)
            else:
                a = arrow([x, top + 0.02, 0], [x, y_hi, 0], width=5, buff=0.0, both=True)
            t = text(label, 23, TEXT)
            t.move_to([x + 0.25 + t.width / 2, (y_hi + top) / 2, 0])
            add(a, t)

        out = node("Report", "+ detection hints", w=3.6, h=1.6,
                   fill=GREEN, edge=GREEN_EDGE, title_size=28, sub_size=22).move_to([9.0, BAR_Y, 0])
        add(out, arrow(bar.get_right(), out.get_left(), GREEN_EDGE, width=6, buff=0.05))
