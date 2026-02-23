---
title: "Contributing to Prime Radiant"
description: "Guidelines for contributing to the Prime Radiant project."
template: "TEMPLATE.documentation-standard"
version: "0.1.0"
last_updated: "2026-01-14"
author: "Project Team"
tags: ["contributing", "guidelines", "development"]
categories: ["project"]
difficulty: "beginner"
prerequisites: []
related_docs:
  - "README.md"
  - "../developers/quick-start/README.md"
dependencies: []
llm_context: "high"
search_keywords: ["contributing", "contribution", "guidelines", "pull request"]
---

# Contributing to Prime Radiant

## Welcome

Thank you for your interest in contributing to Prime Radiant! This document explains how to contribute effectively.

## Ways to Contribute

### Code Contributions

- **Lambda Functions**: Implement new normalizers or handlers
- **Shared Packages**: Add utilities to `packages/shared`
- **Bug Fixes**: Fix issues in existing code
- **Tests**: Add or improve test coverage

### Documentation

- **Guides**: Write how-to guides for common tasks
- **Examples**: Add code examples and tutorials
- **Corrections**: Fix errors or clarify confusing content

### Schema & API

- **Schema Extensions**: Propose additions to the canonical model
- **API Improvements**: Suggest API enhancements

## Before You Start

### 1. Understand the Codebase

- Read the [Architecture Overview](../architecture/README.md)
- Review the [Canonical Model](../architecture/CANONICAL-MODEL.md)
- Understand the [Lambda Conventions](../developers/guides/lambda-conventions.md)

### 2. Check Existing Issues

Before starting work:
- Check if an issue already exists
- If not, create one to discuss your proposed change
- Wait for feedback before significant work

### 3. Set Up Your Environment

Follow the [Development Setup Guide](../developers/quick-start/development-setup.md) to prepare your environment.

## Making Changes

### 1. Create a Branch

```bash
# Create a feature branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/issue-description
```

Branch naming conventions:
- `feature/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation changes
- `refactor/` - Code refactoring

### 2. Make Your Changes

Follow these guidelines:

#### Code Changes

- Follow [Go Patterns](../developers/best-practices/go-patterns.md)
- Use [proper error handling](../developers/best-practices/error-handling.md)
- Add [structured logging](../developers/best-practices/logging.md)
- Write tests for new code
- Update documentation if needed

#### Lambda Changes

- Follow [Lambda Conventions](../developers/guides/lambda-conventions.md)
- Include README.md documentation
- Add unit tests
- Update Makefile targets

#### Schema Changes

- Follow the [Schema Contribution Guide](../developers/guides/schema-contributions.md)
- Document design decisions
- Consider backwards compatibility
- Update related documentation

### 3. Test Your Changes

```bash
# Run unit tests
make test

# Run with coverage
make test-coverage

# Lint code
make lint

# Format code
make fmt
```

### 4. Commit Your Changes

Use conventional commit format:

```
type(scope): brief description

Longer description if needed.

- Bullet points for details
- Another detail

Closes #123
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `refactor`: Code refactoring
- `test`: Adding tests
- `chore`: Maintenance

**Examples:**

```bash
git commit -m "feat(normalizer): add Nessus severity mapping

- Map Nessus risk factors to normalized scores
- Handle edge cases for missing risk data
- Add comprehensive test cases

Closes #45"
```

```bash
git commit -m "docs(guides): add API integration guide

- Document ingestion API usage
- Add query API examples
- Include error handling patterns"
```

### 5. Push and Create PR

```bash
# Push your branch
git push origin feature/your-feature-name
```

Create a pull request with:
- Clear title describing the change
- Description of what and why
- Link to related issue
- Screenshots if UI changes

## Pull Request Guidelines

### PR Checklist

Before submitting:

- [ ] Code follows project conventions
- [ ] Tests pass locally
- [ ] New tests added for new code
- [ ] Documentation updated
- [ ] No linting errors
- [ ] Commit messages follow convention
- [ ] PR description is clear

### PR Description Template

```markdown
## Summary

Brief description of changes.

## Changes

- Change 1
- Change 2

## Testing

How were changes tested?

## Related Issues

Closes #123

## Checklist

- [ ] Tests pass
- [ ] Documentation updated
- [ ] Code follows conventions
```

### Review Process

1. **Automated Checks**: CI runs tests and linting
2. **Code Review**: Maintainer reviews changes
3. **Feedback**: Address any requested changes
4. **Approval**: Maintainer approves PR
5. **Merge**: PR is merged to main branch

## Code Review

### What Reviewers Look For

- **Correctness**: Does the code work?
- **Tests**: Are there adequate tests?
- **Style**: Does it follow conventions?
- **Clarity**: Is it easy to understand?
- **Documentation**: Is it documented?

### Responding to Feedback

- Address all comments
- Explain your reasoning if you disagree
- Ask for clarification if needed
- Update code as requested

## Documentation Contributions

### Documentation Standards

- Use YAML front-matter
- Follow existing templates
- Include code examples
- Link to related docs

### Documentation Structure

```markdown
---
title: "Document Title"
description: "Brief description"
template: "TEMPLATE.documentation-standard"
...
---

# Title

## Purpose

What this document is for.

## When to Use

When to reference this document.

## Content

Main content...

## Related Documentation

Links to related docs.
```

## Community Guidelines

### Be Respectful

- Be welcoming to newcomers
- Be patient with questions
- Give constructive feedback
- Assume good intentions

### Communication

- Use clear, concise language
- Provide context for questions
- Search before asking
- Share knowledge freely

## Getting Help

### Resources

- [Quick Start Guide](../developers/quick-start/README.md)
- [Glossary](GLOSSARY.md)
- [Architecture Docs](../architecture/README.md)

### Questions

- Check documentation first
- Search existing issues
- Create an issue for questions

## License

By contributing, you agree that your contributions will be licensed under the project's license.

---

_Thank you for contributing to Prime Radiant!_
