
1. Install `uv`

2. Clone the repo
```shell
git clone https://github.com/haeter525/rule_score_auto_adjust.git
```

3. Install dependencies using `uv`
```shell
cd rule_score_auto_adjust
uv sync
```

4. Install Quark-Engine
```shell
git clone https://github.com/haeter525/quark-engine.git ../quark-engine -b for_rule_adjust
uv pip install ../quark-engine
```
> The reason is to get the analysis result (confidence level) quick and easy.

5. Prepare `.env` file and define keys
```shell
cp .env.template .env
```

6. Load the `.env` file
```
cp .env.template .env
```

7. Run scripts. Take download APKs as an example.
```
uv run tools/collect_apk_by_family.py --help
```

8. It's recommended to open this project using the `rule_score_auto_adjust_haeter.code-workspace` file.
