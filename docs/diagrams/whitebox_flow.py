"""Diagram 2: white-box at a glance (docs/images/whitebox-flow.png)."""
from manim import Scene, VGroup, DOWN, UP, LEFT, RIGHT
from style import *

setup(22, 10)

STAGES = [
    ("Survey", "surveyor", "Maps the code and entry points", NODE, NODE_EDGE),
    ("Plan", "planner", "Turns the survey into prioritised leads", NODE, NODE_EDGE),
    ("Investigate", "investigator-1..N", "Parallel agents, three leads each", NODE, NODE_EDGE),
    ("Prove", "prover-1..M", "Parallel agents confirm findings, record chains", NODE, NODE_EDGE),
    ("Review", "reviewer", "Adversarial critique and recall-floor audit", NODE, NODE_EDGE),
    ("Patch", "PatchWorkflow", "Fix branch per finding, each fix verified", PURPLE, PURPLE_EDGE),
    ("Report", "reporter", "Evidence-backed report and summary", NODE, NODE_EDGE),
]
W, GAP, Y = 2.6, 0.45, 0.4


class WhiteboxFlow(Scene):
    def construct(self):
        x0 = -(7 * W + 6 * GAP) / 2 + W / 2
        boxes, descs = [], []
        for i, (t, actor, d, fill, edge) in enumerate(STAGES):
            x = x0 + i * (W + GAP)
            b = node(f"{i + 1}  {t}", actor, w=W, h=1.7, fill=fill, edge=edge,
                     title_size=30, sub_size=21).move_to([x, Y, 0])
            desc = text(d, 21, MUTED).scale_to_fit_width(W - 0.1) if False else None
            words = d.split()
            half = (len(words) + 1) // 2
            desc = VGroup(text(" ".join(words[:half]), 21, MUTED),
                          text(" ".join(words[half:]), 21, MUTED)).arrange(DOWN, buff=0.08)
            if desc.width > W + 0.3:
                desc.scale_to_fit_width(W + 0.3)
            desc.next_to(b, DOWN, buff=0.35)
            boxes.append(b); descs.append(desc)
        arrows = [arrow(boxes[i].get_right(), boxes[i + 1].get_left(), width=5, buff=0.05)
                  for i in range(6)]

        inp = node("Source repository + running app", "the app is optional but recommended",
                   w=6.2, h=1.3, fill=PANEL, edge=ACCENT, title_size=26, sub_size=20)
        inp.move_to([boxes[0].get_x() + 1.8, 3.6, 0])
        a_in = arrow(inp.get_bottom() + LEFT * 1.8, boxes[0].get_top(), width=5, buff=0.05)

        side = node("supply-chain + integrity", "start after the survey, feed the review (full preset)",
                    w=7.4, h=1.3, fill=PURPLE, edge=PURPLE_EDGE, title_size=26, sub_size=20)
        side.move_to([boxes[4].get_x() - 0.6, 3.6, 0])
        a_side = arrow([boxes[4].get_x(), 3.6 - 0.65, 0], boxes[4].get_top(), PURPLE_EDGE, width=4, buff=0.05)

        out = node("Report + patches", "patches only when the preset includes remediation",
                   w=9.0, h=1.3, fill=GREEN, edge=GREEN_EDGE, title_size=30, sub_size=21)
        out.move_to([boxes[6].get_x() - 3.4, -3.4, 0])
        a_out1 = arrow([boxes[6].get_x(), -2.1, 0], [boxes[6].get_x(), -2.75, 0], GREEN_EDGE, width=5, buff=0)
        a_out2 = arrow([boxes[5].get_x(), -2.1, 0], [boxes[5].get_x(), -2.75, 0], GREEN_EDGE, width=5, buff=0)
        legend = text("Purple stages depend on the preset: Patch runs for vuln_patch and full, supply-chain and integrity for full.",
                      21, MUTED).move_to([0, -4.6, 0])
        legend.scale_to_fit_width(min(legend.width, 20))
        self.add(*boxes, *descs, *arrows, inp, a_in, side, a_side, out, a_out1, a_out2, legend)
