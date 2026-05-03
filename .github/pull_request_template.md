# The Detrudr Project Pull Request Template/Guide

## Section 1: PR Title

All PR Titles must follow the [Conventional Commit](https://www.conventionalcommits.org/en/v1.0.0/) format.

E.g. `feat(auth): add password reset functionality`

For branch naming, see the 'Your First Code/Documentation Contribution' section of our [CONTRIBUTING.md](../CONTRIBUTING.md) file.

## Section 2: PR Body

### Description

Brief summary of what this PR does.

### Motivation / Purpose

Why is this change needed?

- What problem does it solve?
- What gap does it address?
- Why now?

### Related Issues

Closes #[issue_number]  
Related to #[issue_number]

> If no issue exists, briefly explain why.

### Type of Change

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (changes existing behavior)
- [ ] Documentation update
- [ ] Refactor / Code cleanup
- [ ] Performance improvement
- [ ] Test improvement
- [ ] Build / CI / Dev tooling
- [ ] Other (please describe):

### Changes Introduced

High-level overview of what changed:

-
-
-

> Keep it concise but clear. Prefer bullet points over long paragraphs.

### How Has This Been Tested?

Describe how you validated the changes.

- [ ] Unit tests (`cargo test --lib`)
- [ ] Integration tests (`cargo test --test '*'`)
- [ ] Manual testing
- [ ] Benchmarks (if performance related)

Additional details:

### Breaking Changes (If Applicable)

- Does this require migration?
- Are there API changes?
- Does documentation need updates?

Migration steps (if any):

### Screenshots / Logs (If Applicable)

Add relevant output, logs, or screenshots where helpful.

### Checklist

- [ ] ALL AI(ARTIFICIAL INTELLIGENCE)-GENERATED CODE/CONTENT WAS REVIEWED AND REFACTORED WHERE NECESSARY
- [ ] Code follows project style guidelines
- [ ] Self-review completed
- [ ] Tests added or updated where necessary
- [ ] All tests pass locally
- [ ] No new warnings introduced
- [ ] Documentation updated (if required)
- [ ] Conventional Commit format used for PR title
- [ ] Branch named according to CONTRIBUTING.md (e.g. <preferred_code_name>_dev)
- [ ] CI passes
