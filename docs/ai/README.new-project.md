---
title: "New Project Setup Guide"
description: "Quick reference guide for setting up a new project folder from the template, including directory structure, PRD preparation, and task file setup."
template: "TEMPLATE.documentation-standard"
version: "1.0.0"
last_updated: "2025-01-08"
author: "Project Team"
tags: ["project-setup", "templates", "workflow", "quick-start"]
categories: ["operations", "project-management"]
difficulty: "beginner"
prerequisites: []
related_docs:
  - "README.task-management.md"
  - "ABOUT.documentation.md"
dependencies: []
llm_context: "high"
search_keywords: ["new project", "project setup", "template copy", "project initialization", "prd setup", "task setup"]
---

# New Project Setup Guide

## Purpose

This guide provides step-by-step instructions for setting up a new project folder from the template. This is about **structure only** - not filling out content. Content development (PRD details, task definitions) happens in the planning phase.

## When to Use

- Starting a new project within the style-guide boilerplate
- Need to quickly set up project directory structure
- Want to establish proper project organization from the start

## Quick Reference

### 1. Copy Template Directory

```bash
# Navigate to projects directory
cd projects/

# Copy template-project to your new project name
cp -r template-project my-new-project

# Navigate to new project
cd my-new-project
```

### 2. Project Structure

Your new project will have this structure:

```
projects/my-new-project/
├── PRD.txt              # Product Requirements Document template
├── plans/               # Project planning documents
│   └── example-plan.md  # Example plan to reference/replace
├── resources/           # Project resources (diagrams, assets, etc.)
│   └── README.md        # Resource organization guide
└── tasks/               # Task management files
    ├── example-tasks.json     # Full task schema example
    └── task-list-1.json       # Empty task list to start with
```

### 3. Prepare Files (Structure Only)

#### PRD.txt

The PRD template is already in place with all section headings. **Do not fill it out yet.**

Structure includes:
- Project Overview (name, version, date, author)
- Objectives
- Target Audience
- Technical Requirements
- Success Criteria
- Timeline
- Dependencies
- Risks
- Notes

**Action**: Keep the template structure. Fill this out during planning phase.

#### Task Files

Two task file templates are provided:

**example-tasks.json**: Complete example with JSON Schema and sample tasks
- Shows the full schema structure
- Contains example tasks with all fields
- Use this as a **reference** for field definitions
- **Do not use this file directly**

**task-list-1.json**: Empty starter template
- Contains minimal structure ready to populate
- Use this file to start adding your tasks
- Rename if needed (e.g., `sprint-1.json`, `mvp-tasks.json`)

**Action**: Keep both files. Reference `example-tasks.json` when creating tasks in `task-list-1.json` during planning.

#### Plans Directory

Contains `example-plan.md` showing how to structure project plans.

**Action**: 
- Keep or delete `example-plan.md` based on preference
- Create your actual plan file during planning phase (e.g., `project-plan.md`, `sprint-plan.md`)

#### Resources Directory

Contains a README explaining how to organize project resources.

**Action**: Keep the structure. Add actual resources (diagrams, mockups, etc.) as needed during development.

## Setup Checklist

When setting up a new project folder:

- [ ] Copy `template-project` directory to new project name
- [ ] Verify all directories exist (PRD.txt, plans/, resources/, tasks/)
- [ ] Confirm PRD.txt template is present
- [ ] Confirm task files are present (example-tasks.json, task-list-1.json)
- [ ] Review example-plan.md structure
- [ ] **Stop here** - Do not fill out content yet

## What NOT to Do

❌ **Don't fill out the PRD** - That's for planning phase
❌ **Don't create tasks yet** - That's for planning phase
❌ **Don't delete example files** - They serve as reference
❌ **Don't modify the schema** - Use the provided JSON Schema structure

## What Happens Next

After project folder setup:

1. **Planning Phase**: 
   - Fill out PRD.txt with actual project details
   - Create tasks in task-list-1.json following the schema
   - Define project timeline and milestones
   - Identify dependencies and risks

2. **Development Phase**:
   - Work through tasks in priority order
   - Update task status as work progresses
   - Add resources to resources/ directory
   - Create additional planning docs in plans/

## Task File Reference

### Minimal Task Structure

```json
{
  "project": {
    "name": "My New Project",
    "version": "1.0.0"
  },
  "tasks": [
    {
      "id": "1",
      "title": "Task title",
      "description": "Brief description",
      "details": "Detailed implementation notes",
      "status": "pending",
      "priority": "high",
      "dependencies": [],
      "testStrategy": "How to verify completion"
    }
  ]
}
```

### Status Values

- `pending` - Not started (default)
- `in_progress` - Currently being worked on
- `completed` - Finished
- `blocked` - Waiting on external dependency

### Priority Values

- `low` - Can be deferred
- `medium` - Normal priority
- `high` - Critical path

## Validation

After creating tasks (during planning phase):

```bash
# Validate task file structure
node scripts/validate-tasks.js projects/my-new-project/tasks/task-list-1.json

# Validate all task files in project
node scripts/validate-tasks.js projects/my-new-project/tasks/*.json
```

## Examples

### Example: Creating "Mobile App MVP" Project

```bash
# 1. Copy template
cd projects/
cp -r template-project mobile-app-mvp

# 2. Verify structure
ls -la mobile-app-mvp/
# Should see: PRD.txt, plans/, resources/, tasks/

# 3. Done - ready for planning phase
```

### Example: Project Directory After Planning

```
projects/mobile-app-mvp/
├── PRD.txt                    # Filled out with mobile app details
├── plans/
│   └── sprint-1-plan.md      # Created during planning
├── resources/
│   ├── app-mockups.png       # Added design mockups
│   └── architecture.md       # Added architecture doc
└── tasks/
    ├── example-tasks.json    # Reference (unchanged)
    └── sprint-1-tasks.json   # Filled with actual tasks
```

## Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| Template not found | Ensure you're in `projects/` directory |
| Permission denied | Check file permissions with `ls -la` |
| Can't copy directory | Use `cp -r` for recursive copy |

### Getting Help

- Review [README.task-management.md](README.task-management.md) for task format details
- Check `projects/template-project/tasks/example-tasks.json` for complete schema
- See [ABOUT.documentation.md](../ABOUT.documentation.md) for documentation standards

## Quick Command Reference

```bash
# Copy template
cp -r projects/template-project projects/[new-project-name]

# Navigate to new project
cd projects/[new-project-name]

# List structure
ls -la

# Validate tasks (after creating them)
node scripts/validate-tasks.js tasks/*.json
```

## Summary

**Setup Phase (This Guide)**:
1. Copy template directory
2. Verify structure exists
3. Keep all template files as-is

**Planning Phase (Next Step)**:
1. Fill out PRD.txt
2. Create tasks in task-list-1.json
3. Add planning documents
4. Define project scope and timeline

**Development Phase (Later)**:
1. Execute tasks
2. Update task status
3. Add resources as needed
4. Track progress

---

_This guide focuses on structure setup only. Content development happens in the planning phase._


