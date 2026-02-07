
### How to setup the environment

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
set -a && source .env && set +a
```

7. Run scripts. Take download APKs as an example.
```
uv run tools/collect_apk_by_family.py --help
```

8. It's recommended to open this project using the `rule_score_auto_adjust_haeter.code-workspace` file.

### How to run the process

![alt text](process_of_preparing_rules_for_malware_family.png)


## Notes

To query sample count, find @malwarebazaar.http
```shell
curl --request POST   --url https://mb-api.abuse.ch/api/v1/   --header 'auth-key: af4cf9c57a2e6d8b450e95b4c76a484f9e515b32df8c89dd'   --header 'content-type: application/x-www-form-urlencoded'   --header 'user-agent: vscode-restclient'   --data query=get_siginfo   --data signature=Antidot   --data limit=50 > ./research/antidot/antidot_result.json
```

To convert response into sha256 list
```shell
FAMILY="toxicpanda"
jq '.data.[].sha256_hash' ./research/$FAMILY/${FAMILY}_result.json | tr -d '"' | sed -e '1isha256,' -e 's/$/,/' > ./research/$FAMILY/$FAMILY.csv
```

To download samples
```shell
uv run ./tools/download_apk_malware_bazaar.py --apk_list ./research/antidot/antidot.csv
```

To check if Quark can analyze it
```shell
cd ../quark-rules/; git reset origin/master --hard && git pull origin master
mlr --csv --headerless-csv-output cut -f sha256 ./research/antidot/antidot.csv | parallel -v 'uv run quark -a {} -r ../quark-rules/rules -o {}.json -a ../../data/apks/{}.apk'
```

Search report or news for well-known behaviors
-> NotebookLM

Copy sample list and samples to local
```shell
scp pavi-jack:/mnt/storage/haeter/rule_score_auto_adjust_haeter/research/antidot/antidot.csv ./antidot/
mlr --csv --headerless-csv-output cut -f sha256 ./antidot/antidot.csv | xargs -I FILE scp pavi-jack:/mnt/storage/data/apks/FILE.apk ./antidot/
```
