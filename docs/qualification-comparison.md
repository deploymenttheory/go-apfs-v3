# Comparing complete qualification campaigns

The comparison command reads original evidence from two complete campaigns.
It does not execute acceptance tests or Apple filesystem programs. Each campaign
must have its own successful CI and native workflow, an exact committed source
checkout and the same reviewed Apple input pin. Filesystem production code,
filesystem assertions and native helper sources must agree.

```sh
python3 acceptance/qualification/compare_campaigns.py \
  --repository deploymenttheory/go-apfs-v3 \
  --baseline-root /tmp/original-source \
  --baseline-ci-run ORIGINAL_CI_RUN \
  --baseline-native-run ORIGINAL_NATIVE_RUN \
  --candidate-root /tmp/candidate-source \
  --candidate-ci-run CANDIDATE_CI_RUN \
  --candidate-native-run CANDIDATE_NATIVE_RUN \
  --workspace /tmp/campaign-comparison
```

Use existing GitHub authentication through `GITHUB_TOKEN`, `GH_TOKEN` or `gh`.
The workspace must be absent and outside both source checkouts. The command
uses the existing CI/native admission controllers to authenticate the complete
original jobs and artifact inventory. The Go inspector rechecks original plans,
events, source snapshots, receipts, outputs and their authenticated origins
against each campaign's source checkout. Saved status flags cannot substitute
for that admission. Failed or incomplete originals prevent comparison.

The case index retains actual invocation origins, tools, flags and receipt
digests once per invocation. Case input identities use the existing source-version
projection, including primary and auxiliary inputs. Source versions, hosts,
architectures, compiler settings, race modes, required controls, formats and
native verifier environments remain distinct. A different source dataset is
another obligation. Missing scopes fail agreement; additional scopes and the
number of actually repeated scopes are reported separately.

Deterministic plaintext images and AppleDouble outputs compare by their actual
byte counts and SHA-256 values. Randomized ciphertext is admitted through the
original checks, including the native workflow's individual ciphertext checks;
the comparison does not equate its raw bytes. Native-modified continuation
sources can include current timestamps, so their original unique hashes remain
in the evidence and each campaign must retain its complete continuation proof.
JSON observations and workspace manifests use their original assertions rather
than a raw serialization equality claim. Unknown output formats need an
explicit policy. The report separates outputs compared by bytes from outputs
admitted without that comparison.

`comparison.json` records the source revisions, original run IDs, shared input
pin, production identity, assertion-source digests, inspector digest and every
missing or changed scope. Original evidence and the full case indexes remain
beside it. A scope disagreement returns a failure status.

Scope agreement contributes evidence to the required-check cutover; it does not
authorize retiring tests or gates by itself. Review the original process bounds
and scheduling changes as well. The existing gates remain required until the
complete equivalence and coverage review is accepted. Three comparable warm
campaign measurements, the runner-minute and job-start targets, and retirement
of the superseded execution paths remain separate completion requirements.
