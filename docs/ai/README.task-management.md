---
title: "Task Management System"
description: "Complete guide to the JSON Schema-based task management system, including format specifications, usage guidelines, and AI agent integration."
template: "TEMPLATE.documentation-standard"
version: "1.0.0"
last_updated: "2025-01-03"
author: "Project Team"
tags: ["task-management", "json-schema", "project-tracking", "ai-agents"]
categories: ["development", "operations"]
difficulty: "beginner"
prerequisites: ["json", "project-structure"]
related_docs:
  - "ABOUT.documentation.md"
  - "AGENTS.md"
dependencies: []
llm_context: "high"
search_keywords:
  [
    "task management",
    "tasks.json",
    "json schema",
    "project tracking",
    "task status",
    "dependencies",
  ]
---

# Task Management System

## Purpose

This document provides a complete guide to the JSON Schema-based task management system used in this project. It explains the task file format, field definitions, status values, dependency tracking, and how AI agents should interact with tasks.

## When to Use

- **Creating new projects** - Set up task files for project tracking
- **Working on tasks** - Understand how to read and update tasks
- **Managing dependencies** - Track relationships between tasks
- **AI agent integration** - Guide AI systems on task interaction
- **Project planning** - Structure tasks for project execution

## How to Use

### Quick Start

1. **Create task file**: Use `projects/template-project/tasks/example-tasks.json` as a template
2. **Define project**: Add project metadata (name, version)
3. **Add tasks**: Create task objects following the schema
4. **Track progress**: Update task status as work progresses
5. **Validate**: Use validation script to ensure compliance

### Task File Location

Task files are located in:
```
projects/[project-name]/tasks/[task-file].json
```

Example:
```
projects/init/tasks/init-project.json
projects/template-project/tasks/example-tasks.json
```

## What It Is

### JSON Schema Format

Tasks follow JSON Schema Draft 7 specification, ensuring:
- **Type safety**: Proper data types for all fields
- **Validation**: Automatic validation of task structure
- **Consistency**: Standardized format across projects
- **Tooling**: Compatible with JSON Schema validators

### Task File Structure

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "Project Tasks",
  "description": "Task management file",
  "type": "object",
  "properties": {
    "project": { ... },
    "tasks": { ... }
  },
  "required": ["project", "tasks"]
}
```

## Task Schema Definition

### Project Metadata

```json
{
  "project": {
    "name": "string",      // Required: Project name
    "version": "string"    // Required: Project version
  }
}
```

### Task Object

Each task follows this schema:

```json
{
  "id": "string",                    // Required: Unique identifier (e.g., "1", "1.1", "2.3")
  "title": "string",                 // Required: Task title
  "description": "string",           // Required: Brief description
  "details": "string",               // Optional: Detailed implementation notes
  "status": "enum",                  // Required: pending|in_progress|completed|blocked
  "priority": "enum",                // Required: low|medium|high
  "dependencies": ["string"],        // Required: Array of task IDs (can be empty)
  "assignedTo": "string",            // Optional: Person or team assigned
  "createdAt": "date-time",          // Optional: ISO 8601 timestamp
  "updatedAt": "date-time",          // Optional: ISO 8601 timestamp
  "testStrategy": "string",          // Optional: How to verify completion
  "subtasks": ["task"]               // Optional: Nested subtasks
}
```

### Field Definitions

#### Required Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `id` | string | Unique task identifier | `"1"`, `"1.1"`, `"2.3"` |
| `title` | string | Task title | `"Implement User Authentication"` |
| `description` | string | Brief description | `"Add login/logout functionality"` |
| `status` | enum | Current status | `"pending"`, `"in_progress"`, `"completed"`, `"blocked"` |
| `priority` | enum | Priority level | `"low"`, `"medium"`, `"high"` |
| `dependencies` | array | Task IDs this depends on | `["1.1", "1.2"]` or `[]` |

#### Optional Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `details` | string | Implementation details | `"Create auth endpoints, middleware, JWT tokens"` |
| `assignedTo` | string | Assignee | `"Developer"`, `"QA Team"` |
| `createdAt` | date-time | Creation timestamp | `"2025-01-01T00:00:00Z"` |
| `updatedAt` | date-time | Last update timestamp | `"2025-01-02T12:00:00Z"` |
| `testStrategy` | string | Verification approach | `"Test login with valid/invalid credentials"` |
| `subtasks` | array | Nested subtasks | Array of task objects |

### Status Values

#### pending
- **Description**: Task not started
- **When to use**: Default status for new tasks
- **Next states**: `in_progress` when starting work

#### in_progress
- **Description**: Currently being worked on
- **When to use**: When actively working on the task
- **Next states**: `completed` when finished, `blocked` if blocked

#### completed
- **Description**: Task finished successfully
- **When to use**: When all requirements are met and verified
- **Next states**: None (final state)

#### blocked
- **Description**: Cannot proceed
- **When to use**: When waiting for external dependency or blocker
- **Next states**: `in_progress` when blocker is resolved

### Priority Values

- **high**: Critical tasks that block other work
- **medium**: Important tasks with normal priority
- **low**: Nice-to-have tasks that can be deferred

### Task IDs

Task IDs follow a hierarchical pattern:
- **Main tasks**: `"1"`, `"2"`, `"3"`
- **Subtasks**: `"1.1"`, `"1.2"`, `"2.1"`
- **Nested subtasks**: `"1.1.1"`, `"1.1.2"`

Pattern: `^[0-9]+(\.[0-9]+)*$`

## Working with Tasks

### Reading Tasks

#### Find Available Tasks

Tasks available for work:
1. Status is `pending`
2. All dependencies have status `completed`
3. No blockers exist

#### Example Query Logic

```javascript
// Pseudocode for finding available tasks
function findAvailableTasks(tasks) {
  return tasks.filter(task => {
    // Status must be pending
    if (task.status !== 'pending') return false;
    
    // All dependencies must be completed
    const allDependenciesCompleted = task.dependencies.every(depId => {
      const depTask = findTaskById(depId);
      return depTask && depTask.status === 'completed';
    });
    
    return allDependenciesCompleted;
  });
}
```

### Updating Tasks

#### Starting Work

```json
{
  "id": "2.1",
  "status": "in_progress",  // Changed from "pending"
  "updatedAt": "2025-01-03T10:00:00Z"
}
```

#### Completing Work

```json
{
  "id": "2.1",
  "status": "completed",   // Changed from "in_progress"
  "updatedAt": "2025-01-03T18:00:00Z"
}
```

#### Blocking Task

```json
{
  "id": "2.2",
  "status": "blocked",     // Changed from "in_progress"
  "details": "Waiting for API endpoint to be deployed",
  "updatedAt": "2025-01-03T14:00:00Z"
}
```

### Dependency Management

#### Understanding Dependencies

```json
{
  "id": "2.1",
  "dependencies": ["1.1", "1.2"]  // Must complete 1.1 AND 1.2 first
}
```

#### Dependency Rules

1. **Check before starting**: Verify all dependencies are `completed`
2. **Update when completing**: Check if other tasks depend on this one
3. **Avoid circular dependencies**: Task A cannot depend on Task B if B depends on A
4. **Validate references**: Ensure all dependency IDs exist

#### Example Dependency Chain

```
Task 1 (no dependencies)
  └─ Task 1.1 (depends on: [])
  └─ Task 1.2 (depends on: ["1.1"])
      └─ Task 2.1 (depends on: ["1.1", "1.2"])
```

## AI Agent Integration

### Reading Tasks

AI agents should:

1. **Locate task file**: Check `projects/[project-name]/tasks/` directory
2. **Parse JSON**: Load and parse task file
3. **Validate schema**: Ensure JSON Schema compliance
4. **Find available tasks**: Identify tasks with `pending` status and completed dependencies
5. **Read task details**: Review `description`, `details`, and `testStrategy`

### Updating Tasks

AI agents should:

1. **Update status**: Change status as work progresses
   - `pending` → `in_progress` when starting
   - `in_progress` → `completed` when finished
   - `in_progress` → `blocked` if blocked
2. **Update timestamps**: Set `updatedAt` when making changes
3. **Validate changes**: Ensure JSON Schema compliance
4. **Commit and push**: After completing each subtask, commit changes and push to GitHub (see Git Workflow section below)

### Task Selection

AI agents should prioritize:

1. **High priority** tasks first
2. **Tasks with fewer dependencies** before complex ones
3. **Blocking tasks** before dependent tasks
4. **Tasks in dependency order** (dependencies before dependents)

### Example AI Workflow

```javascript
// Pseudocode for AI agent task workflow
async function aiAgentWorkflow() {
  // 1. Load tasks
  const tasks = await loadTasks('projects/[project-name]/tasks/[task-file].json');
  
  // 2. Find available tasks
  const available = findAvailableTasks(tasks);
  
  // 3. Select highest priority
  const selected = available.sort((a, b) => {
    const priorityOrder = { high: 3, medium: 2, low: 1 };
    return priorityOrder[b.priority] - priorityOrder[a.priority];
  })[0];
  
  // 4. Update status to in_progress
  selected.status = 'in_progress';
  selected.updatedAt = new Date().toISOString();
  
  // 5. Work on task (implementation)
  await implementTask(selected);
  
  // 6. Update status to completed
  selected.status = 'completed';
  selected.updatedAt = new Date().toISOString();
  
  // 7. Save and commit
  await saveTasks(tasks);
  await commitChanges(`feat: complete task ${selected.id} - ${selected.title}`);
  
  // 8. Push to GitHub
  await pushToGitHub();
}
```

## Git Workflow and Version Control

### Standard Operating Procedure: Commit After Each Subtask

**CRITICAL**: After completing each subtask, you MUST commit and push changes to GitHub.

### Workflow Steps

1. **Complete the subtask**
   - Finish implementation
   - Update task status to `completed`
   - Update `updatedAt` timestamp
   - Verify code works (type-check, lint, build if applicable)

2. **Stage changes**
   ```bash
   git add .
   ```

3. **Commit with task reference**
   ```bash
   git commit -m "feat: complete task [TASK_ID] - [Task Title]

   - [Brief description of what was implemented]
   - Updated task status to completed
   - [Any other relevant changes]
   
   Task: [TASK_ID]"
   ```

4. **Push to GitHub**
   ```bash
   git push origin [branch-name]
   ```

### Commit Message Format

Follow conventional commits format with task ID reference:

```
<type>: complete task <TASK_ID> - <Task Title>

<Description of changes>

Task: <TASK_ID>
```

**Types**:
- `feat`: New feature implementation
- `fix`: Bug fix
- `refactor`: Code refactoring
- `docs`: Documentation updates
- `test`: Test additions/updates
- `chore`: Maintenance tasks

**Examples**:

```bash
# Feature implementation
git commit -m "feat: complete task 2.5 - Fix ingestion API type issues

- Replaced (db as any) casts with proper PostgreSQL type validation
- Added runtime database provider validation
- Improved error handling for database configuration

Task: 2.5"

# Bug fix
git commit -m "fix: complete task 4.2.1 - Fix workflow run detail data transformation

- Fixed incorrect step data transformation in run detail view
- Added proper status calculation from events
- Fixed timeline view rendering

Task: 4.2.1"

# Documentation
git commit -m "docs: complete task 2.4 - Document ingestion API

- Added comprehensive API documentation
- Included example payloads and client snippets
- Documented authentication and error handling

Task: 2.4"
```

### What to Include in Commits

**Always include**:
- Code changes (new files, modified files)
- Task file updates (`projects/[project-name]/tasks/[task-file].json`)
- Documentation updates (if applicable)
- Test files (if applicable)

**Never include**:
- Build artifacts (`dist/`, `.next/`, etc.)
- Dependencies (`node_modules/`, `package-lock.json` unless dependency changes)
- Environment files (`.env`, `.env.local`)
- IDE-specific files (`.vscode/`, `.idea/`)

### Branch Strategy

- **Main branch**: `main` or `master` (protected, requires PR)
- **Feature branches**: `feature/task-[TASK_ID]` or `task/[TASK_ID]`
- **Direct commits**: Only for small fixes or documentation updates

### When to Commit

**Commit immediately after**:
- Completing a subtask (status → `completed`)
- Fixing a bug related to a task
- Updating task status or metadata
- Making related documentation updates

**Do NOT wait to commit**:
- Until multiple tasks are done
- Until end of day/session
- Until a "logical unit" is complete (commit each subtask separately)

### Benefits of This Workflow

1. **Progress tracking**: Each commit represents a completed subtask
2. **Rollback capability**: Easy to revert specific task implementations
3. **Code review**: Smaller, focused commits are easier to review
4. **History clarity**: Git history shows clear progression through tasks
5. **Collaboration**: Team members see progress in real-time
6. **Backup**: Changes are safely stored on GitHub

### Troubleshooting Git Issues

**If commit fails**:
```bash
# Check git status
git status

# See what files changed
git diff

# If merge conflicts, resolve then:
git add .
git commit -m "fix: resolve merge conflicts for task [TASK_ID]"
git push
```

**If push fails**:
```bash
# Pull latest changes first
git pull origin [branch-name]

# Resolve any conflicts, then:
git add .
git commit -m "fix: sync with remote for task [TASK_ID]"
git push origin [branch-name]
```

## Validation

### JSON Schema Validation

Task files must comply with JSON Schema:

```bash
# Validate using ajv-cli
npx ajv-cli validate -s task-schema.json -d projects/*/tasks/*.json

# Or use custom validation script
node scripts/validate-tasks.js
```

### Validation Rules

1. **Required fields**: All required fields must be present
2. **Type checking**: Fields must match specified types
3. **Enum values**: Status and priority must use valid enum values
4. **ID format**: Task IDs must match pattern `^[0-9]+(\.[0-9]+)*$`
5. **Dependencies**: All dependency IDs must exist
6. **No circular dependencies**: Tasks cannot create circular dependency chains

### Validation Script

See `scripts/validate-tasks.js` for complete validation implementation.

## Examples

### Complete Task File Example

See `projects/template-project/tasks/example-tasks.json` for a complete example with:
- Project metadata
- Multiple tasks with different statuses
- Subtasks and nested structure
- Dependencies
- All field types

### Simple Task Example

```json
{
  "project": {
    "name": "My Project",
    "version": "1.0.0"
  },
  "tasks": [
    {
      "id": "1",
      "title": "Setup Project",
      "description": "Initialize project structure",
      "status": "completed",
      "priority": "high",
      "dependencies": []
    }
  ]
}
```

## Troubleshooting

### FAQ

**Q: What if a task file is invalid JSON?**
A: Use a JSON validator to identify syntax errors. Common issues: trailing commas, missing quotes, incorrect brackets.

**Q: How do I handle circular dependencies?**
A: Restructure tasks to break the cycle. Consider combining tasks or splitting them differently.

**Q: Can I add custom fields?**
A: Yes, but they won't be validated by the schema. Document custom fields in project README.

**Q: How do I track task history?**
A: Use Git commits to track task file changes. Include task IDs in commit messages.

**Q: What if a dependency task is deleted?**
A: Update dependent tasks to remove the deleted dependency ID, or restore the deleted task.

### Common Issues

| Issue | Symptoms | Solution |
|-------|----------|----------|
| Invalid JSON | Parse errors | Validate JSON syntax, check for trailing commas |
| Missing required field | Validation errors | Add all required fields from schema |
| Invalid status | Validation errors | Use only: pending, in_progress, completed, blocked |
| Circular dependency | Logic errors | Restructure tasks to break cycle |
| Missing dependency | Runtime errors | Ensure all dependency IDs exist |

### Debugging Steps

1. **Validate JSON**: Check JSON syntax is valid
2. **Validate schema**: Run validation script
3. **Check dependencies**: Verify all dependency IDs exist
4. **Review status**: Ensure status values are valid
5. **Test logic**: Verify task selection logic works correctly

## Related Documentation

- **[AGENTS.md](../../AGENTS.md)**: AI agent guidance and workflows
- **[ABOUT.documentation.md](../ABOUT.documentation.md)**: Documentation system standards
- **Example Tasks**: `projects/template-project/tasks/example-tasks.json`

## LLM Context

This task management system uses JSON Schema for structured task tracking. Key concepts for AI understanding:

- **JSON Schema**: Industry-standard format for data validation
- **Task Lifecycle**: pending → in_progress → completed (or blocked)
- **Dependencies**: Tasks can depend on other tasks being completed first
- **Hierarchical IDs**: Tasks can have subtasks with nested IDs (1.1, 1.2, etc.)
- **Status Tracking**: Four states track task progress
- **Validation**: All task files must comply with JSON Schema

When working with tasks, AI agents should:
- Always check task status and dependencies before starting
- Update task status as work progresses
- Validate task files before committing
- Reference task IDs in commit messages
- Follow dependency order when selecting tasks

---

_This document follows the project Documentation Standard. For questions about documentation structure, see [ABOUT.documentation.md](../ABOUT.documentation.md)._

