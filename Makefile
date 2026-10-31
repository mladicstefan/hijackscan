.PHONY: dev test lint fetch-all fetch-%

dev:
	uv sync --all-groups

test:
	uv run pytest

lint:
	uv run ruff check src tests scripts

fetch-all:
	uv run hijackscan fetch all

# make fetch-caida, make fetch-rpki, make fetch-ris, make fetch-tranco, make fetch-bgpy-smoke, make fetch-crtsh
fetch-%:
	uv run hijackscan fetch $*

crtsh-finalize:
	uv run hijackscan fetch crtsh --finalize
