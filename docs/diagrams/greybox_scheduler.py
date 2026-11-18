"""Diagram 5: the grey-box scheduler loop (docs/images/greybox-scheduler.png).

Rules, caps and halt reasons come from src/greybox/scheduler/ (rules.py, core.py, verbs.py).
"""
from manim import Scene, VGroup, DOWN, UP, LEFT, RIGHT
from style import *

setup(22, 12.8)

LOOP_Y = -0.5
BAR_Y = -4.4


class GreyboxScheduler(Scene):
    def construct(self):
        add = self.add
        add(text("Grey-box scheduler: one tick of the loop", 40, ACCENT, bold=True).move_to([0, 5.85, 0]))

        # halt conditions
        halt = panel(20.6, 2.7, None, fill="#2E2140", edge=RED_EDGE).move_to([0, 3.7, 0])
        add(halt, text("Any of these ends the loop (the scheduler emits DONE)", 28, RED_EDGE, bold=True).move_to([-3.2, 4.7, 0]))
        halts = [("coverage complete", "no rule fires, no agent running"),
                 ("budget exhausted", "under 3% of the budget left"),
                 ("diminishing returns", "20 ticks without progress"),
                 ("waiting timeout", "10 ticks only waiting for agents")]
        hn = VGroup(*[node(a, b, w=3.75, h=1.35, fill=RED, edge=RED_EDGE, title_size=24, sub_size=20) for a, b in halts])
        hn.arrange(RIGHT, buff=0.3).move_to([-2.0, 3.4, 0])
        stop = node("Write report", "then stop", w=3.4, h=1.35, fill=GREEN, edge=GREEN_EDGE, title_size=26, sub_size=22)
        stop.move_to([8.2, 3.4, 0])
        add(hn, stop, arrow(hn.get_right(), stop.get_left(), GREEN_EDGE, width=5, buff=0.08))

        # the loop
        read = node("Read the graph", "leads, parameters,\nidentities, access\nmatrix, claims", w=3.0, h=3.0,
                    title_size=28, sub_size=21).move_to([-9.0, LOOP_Y, 0])
        rules = panel(7.2, 5.0, "Fire the rules", None, title_color=TEXT, title_size=30, fill="#222B58", edge=NODE_EDGE)
        rules.move_to([-2.9, LOOP_Y, 0])
        rows = VGroup(*[node(v, d, w=6.7, h=0.92, title_size=23, sub_size=20) for v, d in (
            ("INVESTIGATE_LEAD", "open lead, medium or high signal, attempts left"),
            ("ATTEMPT_CHAIN", "findings that could be combined"),
            ("PROBE_PARAMETERS", "untested parameters, in batches of 15"),
            ("TEST_ACCESS_MATRIX", "allow and deny seen across identities"))])
        rows.arrange(DOWN, buff=0.12).move_to(rules.box.get_center() + DOWN * 0.4)
        emit = node("Emit verbs", "highest priority\nfirst, capped per\ntype; low budget\ndrops PROBE and\nCHAIN",
                    w=3.6, h=3.6, title_size=28, sub_size=21).move_to([3.5, LOOP_Y, 0])
        spawn = node("Spawn agents", "run in parallel;\neach claims its\ntargets so none is\ndispatched twice",
                     w=4.2, h=3.6, fill="#3B2E7E", edge=PURPLE_EDGE, title_size=28, sub_size=21).move_to([8.4, LOOP_Y, 0])
        add(read, rules, rows, emit, spawn)
        for a, b in ((read, rules.box), (rules.box, emit), (emit, spawn)):
            add(arrow(a.get_right(), b.get_left(), width=6, buff=0.06, tip=0.26))
        add(arrow(emit.get_top(), [emit.get_x(), 2.33, 0], RED_EDGE, width=5, buff=0.05, tip=0.24))
        t = text("or DONE", 24, RED_EDGE); t.move_to([emit.get_x() + 0.2 + t.width / 2, 1.9, 0]); add(t)

        # the graph
        bar = node("Knowledge graph", "the only state the scheduler reads; agents write their results back into it",
                   w=20.6, h=1.6, fill=LEDGER, edge=LEDGER_EDGE, title_size=32, sub_size=23).move_to([0, BAR_Y, 0])
        bar_top = BAR_Y + 0.8
        add(bar)
        add(arrow([-9.0, bar_top + 0.02, 0], [-9.0, LOOP_Y - 1.5, 0], width=5, buff=0.0))
        l1 = text("every tick", 24, TEXT); l1.move_to([-9.0 + 0.25 + l1.width / 2, -2.9, 0]); add(l1)
        add(arrow([8.4, LOOP_Y - 1.8, 0], [8.4, bar_top + 0.02, 0], PURPLE_EDGE, width=5, buff=0.0))
        l2 = text("results and verdicts", 24, TEXT); l2.move_to([8.4 - 0.25 - l2.width / 2, -2.9, 0]); add(l2)
