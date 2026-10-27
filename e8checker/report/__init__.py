"""Report renderers. Each takes an Assessment and returns a string."""

import json

from e8checker.engine import Assessment
from e8checker.report.html import render_html
from e8checker.report.markdown import render_markdown


def render_json(assessment: Assessment) -> str:
    return json.dumps(assessment.to_dict(), indent=2)


RENDERERS = {"markdown": render_markdown, "html": render_html, "json": render_json}

__all__ = ["RENDERERS", "render_html", "render_json", "render_markdown"]
