"""Shared route helpers."""
from flask import request

from config import Config


def get_pagination():
    try:
        page = int(request.args.get('page', 0))
    except (TypeError, ValueError):
        page = 0
    try:
        size = int(request.args.get('size', Config.DEFAULT_PAGE_SIZE))
    except (TypeError, ValueError):
        size = Config.DEFAULT_PAGE_SIZE
    return page, size
