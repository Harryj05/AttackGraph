.PHONY: eval test lab-up lab-down lint demo

lab-up:
	docker compose up -d
	docker compose -f docker-compose.crapi.yml up -d

lab-down:
	docker compose down
	docker compose -f docker-compose.crapi.yml down

eval:
	python -m eval.run

test:
	pytest -q

lint:
	flake8 . --count --select=E9,F63,F7,F82 --show-source --statistics

demo:
	python scripts/demo_quickstart.py
