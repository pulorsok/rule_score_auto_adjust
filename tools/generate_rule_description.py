import json
from pathlib import Path
import click
from langchain_openai import ChatOpenAI
from langchain.schema import SystemMessage, HumanMessage
import diskcache
import os
import dotenv

dotenv.load_dotenv()

_CACHE_FOLDER = os.getenv("CACHE_FOLDER") or str(Path(__file__).parent.parent / "data" / "cache")
cache = diskcache.FanoutCache(f"{_CACHE_FOLDER}/crime_description_cache")


class RuleDescriptionAgent:
    def __init__(self, openai_api_key):
        self.system_prompt = """
        You are an AI assistant that generates a single, concise, and clear behavior description that integrates two Android APIs.
        Follow these structured rules:

        1. Start the description with a verb in simple present tense (e.g., Get, Read, Store, Send, Save).
        2. Use simple present tense throughout the description.
        3. Keep it concise—prefer a single verb where possible.
        4. Simplify UI-related terminology for general understanding.
        5. Maintain a consistent pattern: 'Action + Object + Purpose (if necessary)'.
        6. Integrate both APIs into **one** meaningful behavior description instead of generating separate descriptions.

        **Examples:**
        - API 1: Landroid/content/Context;.getPackageName ()Ljava/lang/String;
          API 2: Landroid/app/AlertDialog$Builder;.setAdapter (Landroid/widget/ListAdapter; Landroid/content/DialogInterface$OnClickListener;)Landroid/app/AlertDialog$Builder;
          **Generated Behavior:** Get the package name and set it as an adapter in an AlertDialog.

        - API 1: Landroid/app/Dialog;.findViewById (I)Landroid/view/View;
          API 2: Landroid/content/SharedPreferences$Editor;.putString (Ljava/lang/String; Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;
          **Generated Behavior:** Store a dialog view’s value in SharedPreferences.

        Now, for each of the following messages, I will provide a pair of APIs, please refer to the above examples, and generate a single behavior description.
        """
        self.user_prompt_template = (
            "- API 1: {api1[class]}.{api1[method]} {api1[descriptor]}\n"
            "- API 2: {api2[class]}.{api2[method]} {api2[descriptor]}"
        )
        self.chat_model = ChatOpenAI(model="gpt-4.1-nano", api_key=openai_api_key)

    @cache.memoize(ignore={"self", 0})
    def get_description(self, api_pair) -> str:
        messages = [
            SystemMessage(content=self.system_prompt),
            HumanMessage(
                content=self.user_prompt_template.format(api1=api_pair[0], api2=api_pair[1])
            ),
        ]
        return self.chat_model.invoke(messages).content.strip()  # type: ignore


def get_rule_description(rules: list[Path], openai_api_key: str) -> list[tuple[str, str]]:
    agent = RuleDescriptionAgent(openai_api_key)

    def get_apis_from_rule(rule: Path) -> tuple[dict, dict]:
        with rule.open("r") as file:
            content = json.load(file)
            api1, api2 = content["api"]
            if not api1 or not api2:
                raise ValueError(f"Failed to load APIs from the rule file: {rule}")
            return api1, api2

    descriptions = [
        (str(rule), agent.get_description(get_apis_from_rule(rule)))
        for rule in rules
        if rule.is_file() and rule.suffix == ".json"
    ]

    return descriptions


@click.command()
@click.option(
    "--rule_folder",
    "-r",
    type=click.Path(exists=True, dir_okay=True, path_type=Path),
    help="Path to the folder containing rules.",
)
@click.option(
    "--openai_api_key",
    required=True,
    help="OpenAI API key for accessing the model, defaults to OPENAI_API_KEY environment variable.",
    envvar="OPENAI_API_KEY",
)
@click.option(
    "--write",
    "-w",
    is_flag=True,
    default=False,
    help="Write the generated descriptions to respective rule files.",
)
def entry_point(rule_folder: Path, openai_api_key: str, write: bool):
    """
    Generate behavior descriptions for rules in the specified folder using OpenAI's model.

    Example usage:
    uv run tools/generate_rule_description.py -r data/test_rules --write
    """
    file_description_pairs = get_rule_description(
        rules=list(rule_folder.glob("*.json")),
        openai_api_key=openai_api_key,
    )

    print(
        f"Generated {len(file_description_pairs)} rule descriptions:\n{json.dumps(file_description_pairs, indent=4)}"
    )

    if write:
        print(f"Writing descriptions to rules...")
        for rule, description in file_description_pairs:
            print(f'Writing description "{description}" to {rule}')
            with open(rule, "r+") as file:
                content = json.load(file)
                content["crime"] = description
                file.seek(0)
                json.dump(content, file, indent=4)
                file.truncate()

        print("Descriptions written successfully.")
    else:
        print("Descriptions not written. Use --write to save them to the files.")


if __name__ == "__main__":
    entry_point()
