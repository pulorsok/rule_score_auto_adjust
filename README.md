
1. Clone the repo
```shell
git clone https://github.com/haeter525/rule_score_auto_adjust.git
```

2. Install dependencies using `uv`
```shell
uv sync
```

3. Prepare `.env` file and define keys
```shell
cp .env.template .env
```

4. Load the `.env` file
```
cp .env.template .env
```

5. Run scripts. Take download APKs as an example.
```
uv run tools/collect_apk_by_family.py --help
```
