# Demo: deleted secrets still in history

The real demo lives in its own repository: **[umeraamir69/testKeys](https://github.com/umeraamir69/testKeys)**.

It is kept separate on purpose. Planting fake keys here would put them in SecSentry's own git history, so every `--history` scan of this repo would report them forever, and GitHub secret scanning would flag the main project.

```bash
git clone https://github.com/umeraamir69/testKeys.git
secsentry scan testKeys              # clean tree, 0 findings
secsentry scan testKeys --history    # 11 findings from the deleted commit
```

The history scan reports each finding with its file, line, column, commit, author, and `still_in_head=False`, with the value masked.

Do not use live credentials in any demo.
