"""Diagram 3: white-box engine in detail (docs/images/whitebox-detail.png)."""
from manim import Scene, VGroup, DOWN, UP, LEFT, RIGHT
from style import *

setup(24, 15.2)

PATCH_FILL = "#2B2358"
ROW_Y, ROW_H = 3.9, 4.9          # agent row
LED_Y, LED_H = -1.0, 2.5        # ledger band
BOT_Y, BOT_H = -4.8, 3.0         # patch / report row


def tall(title, lines, x, y, w, h):
    box = panel(w, h, None)
    box.move_to([x, y, 0])
    head = text(title, 32, TEXT, bold=True, max_width=w - 0.4).move_to([x, y + h / 2 - 0.55, 0])
    body = VGroup(*[text(l, 24, MUTED, max_width=w - 0.4) for l in lines]).arrange(DOWN, buff=0.18)
    body.move_to([x, y - 0.3, 0])
    return VGroup(box, head, body)


def agent_group(title, sub, items, x, y, w, h):
    box = panel(w, h, title, sub, title_color=TEXT, title_size=30, edge=NODE_EDGE, fill="#222B58")
    box.move_to([x, y, 0])
    nodes = VGroup(*[node(a, b, w=w - 0.6, h=0.95, title_size=24, sub_size=22) for a, b in items])
    nodes.arrange(DOWN, buff=0.15)
    nodes.move_to([x, y - 0.75, 0])
    return VGroup(box, nodes)


class WhiteboxDetail(Scene):
    def construct(self):
        add = self.add
        add(text("White-box engine: agents coordinate through the findings ledger", 40, ACCENT, bold=True)
            .move_to([0, 6.85, 0]))

        cols = {"survey": -10.1, "plan": -6.3, "inv": -1.3, "prv": 5.0, "rev": 10.1}
        survey = node("Survey", "surveyor", w=3.0, h=1.5, title_size=32, sub_size=24).move_to([cols["survey"], ROW_Y + 0.95, 0])
        side = node("supply-chain", "+ integrity (full preset)\nmerged into the index", w=3.0, h=1.5, fill=PURPLE, edge=PURPLE_EDGE,
                    title_size=28, sub_size=22).move_to([cols["survey"], ROW_Y - 1.05, 0])
        plan = tall("Plan", ["planner", "records leads,", "each with a", "priority"], cols["plan"], ROW_Y, 2.8, ROW_H)
        inv = agent_group("Investigate", "open leads, 3 per agent, up to 8 at once",
                          [("investigator-1", "LEADS: L-001,L-004,L-007"),
                           ("investigator-2", "LEADS: L-002,L-003,L-009"),
                           ("investigator-N", "+ one follow-up round")],
                          cols["inv"], ROW_Y, 5.4, ROW_H)
        prv = agent_group("Prove", "unproven findings, 3 per agent",
                          [("prover-1", "FINDINGS: VG-001,VG-004,VG-006"),
                           ("prover-2", "FINDINGS: VG-002,VG-003,VG-005"),
                           ("prover-M", "each proof or chain recorded")],
                          cols["prv"], ROW_Y, 5.4, ROW_H)
        rev = tall("Review", ["reviewer", "findings index", "adversarial", "critique,", "recall-floor", "audit"],
                   cols["rev"], ROW_Y, 3.0, ROW_H)
        add(survey, side, plan, inv, prv, rev)
        for a, b, y in ((survey, plan, ROW_Y + 0.95), (plan, inv, ROW_Y), (inv, prv, ROW_Y), (prv, rev, ROW_Y)):
            add(arrow([a.get_right()[0], y, 0], [b.get_left()[0], y, 0], width=6, buff=0.06, tip=0.26))

        # ledger band
        ledger = panel(23.2, LED_H, None, fill="#0B3C3F", edge=LEDGER_EDGE).move_to([0, LED_Y, 0])
        ltitle = VGroup(text("Findings ledger", 26, LEDGER_EDGE, bold=True),
                        text("append-only JSONL", 21, MUTED),
                        text("via vigilo-record", 21, MUTED)).arrange(DOWN, buff=0.1)
        ltitle.move_to([cols["survey"], LED_Y, 0])

        def cell(t, s, x, w):
            return node(t, s, w=w, h=1.5, fill=LEDGER, edge=LEDGER_EDGE, title_size=26, sub_size=22).move_to([x, LED_Y, 0])
        c_leads = cell("leads.jsonl", "+ lead_status (closed)", cols["plan"], 2.9)
        c_find = cell("findings.jsonl", "one per finding, duplicate-checked", cols["inv"], 4.6)
        c_ver = cell("verdicts.jsonl", "exploited, refuted, ...", 3.4, 3.1)
        c_chain = cell("chains.jsonl", "multi-step attacks", 6.7, 3.2)
        c_idx = cell("findings_index", "built from the ledger", cols["rev"], 2.8)
        add(ledger, ltitle, c_leads, c_find, c_ver, c_chain, c_idx)

        top = LED_Y + LED_H / 2
        row_bot = ROW_Y - ROW_H / 2
        mid = (top + row_bot) / 2

        def link(x, label, direction="both", lw=2.8):
            lo, hi = [x, row_bot - 0.02, 0], [x, top + 0.02, 0]
            if direction == "both":
                a = arrow(hi, lo, width=5, both=True, buff=0.0, tip=0.24)
            elif direction == "down":
                a = arrow(lo, hi, width=5, buff=0.0, tip=0.24)
            else:
                a = arrow(hi, lo, width=5, buff=0.0, tip=0.24)
            t = text(label, 22, TEXT, max_width=lw)
            t.move_to([x + 0.2 + t.width / 2, mid, 0])
            return a, t
        for a, t in (link(cols["plan"], "leads", "down", 1.2),
                     link(-3.0, "reads leads", "up", 2.2),
                     link(-0.1, "findings", "down", 1.6),
                     link(2.9, "reads findings", "up", 2.4),
                     link(5.6, "verdicts, chains", "down", 2.7),
                     link(cols["rev"], "index", "up", 1.2)):
            add(a, t)

        # side agents feed the index
        add(arrow(side.get_bottom(), [cols["survey"], top + 0.02, 0], PURPLE_EDGE, width=4, buff=0.05))

        # bottom row
        pw = 12.2
        pc = -11.6 + pw / 2
        patch = panel(pw, BOT_H, "PatchWorkflow (child workflow, vuln_patch and full)", None,
                      fill=PATCH_FILL, edge=PURPLE_EDGE, title_color=PURPLE_EDGE, title_size=28).move_to([pc, BOT_Y, 0])
        steps = VGroup(*[node(a, b, w=2.1, h=1.45, fill=PURPLE, edge=PURPLE_EDGE, title_size=24, sub_size=20)
                         for a, b in (("rebuild git", "upstream history"), ("remediator", "fix per finding"),
                                      ("export", ".patch files"), ("verify", "re-run harness"),
                                      ("deliver", "push + MR\nif configured"))])
        steps.arrange(RIGHT, buff=0.28).move_to([pc, BOT_Y - 0.4, 0])
        add(patch, steps)
        for i in range(len(steps) - 1):
            add(arrow(steps[i].get_right(), steps[i + 1].get_left(), PURPLE_EDGE, width=4, buff=0.04, tip=0.2))

        report = node("Report", "reporter", w=3.4, h=1.5, title_size=30, sub_size=24).move_to([4.0, BOT_Y, 0])
        out = node("Report + patches", "evidence, severities, fix branches", w=5.0, h=1.5,
                   fill=GREEN, edge=GREEN_EDGE, title_size=30, sub_size=22).move_to([9.0, BOT_Y, 0])
        add(report, out)
        add(arrow(report.get_right(), out.get_left(), GREEN_EDGE, width=5, buff=0.05))
        bot_top = BOT_Y + BOT_H / 2
        led_bot = LED_Y - LED_H / 2
        add(arrow([pc, led_bot - 0.02, 0], [pc, bot_top, 0], width=5, buff=0.0, tip=0.24))
        add(arrow([4.0, led_bot - 0.02, 0], [4.0, BOT_Y + 0.75, 0], width=5, buff=0.0, tip=0.24))
        add(arrow([pc + pw / 2, BOT_Y, 0], report.get_left(), PURPLE_EDGE, width=4, buff=0.05, tip=0.22))
        lbl = text("fix status", 22, MUTED)
        lbl.move_to([(pc + pw / 2 + report.get_left()[0]) / 2, BOT_Y + 0.4, 0])
        add(lbl)
