const fs = require('fs');
const path = require('path');
const logger = require('./logger');

const TASKS_FILE = path.join(__dirname, 'tasks.json');

/**
 * Loads tasks from the JSON file.
 * @returns {Array} Array of task objects
 */
function loadTasks() {
    try {
        if (!fs.existsSync(TASKS_FILE)) {
            return [];
        }
        const data = fs.readFileSync(TASKS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        logger.error('Error loading tasks:', error);
        return [];
    }
}

/**
 * Saves tasks to the JSON file.
 * @param {Array} tasks Array of task objects
 */
function saveTasks(tasks) {
    try {
        fs.writeFileSync(TASKS_FILE, JSON.stringify(tasks, null, 2), 'utf8');
        return true;
    } catch (error) {
        logger.error('Error saving tasks:', error);
        return false;
    }
}

/**
 * Marks a task as completed.
 * @param {string} taskId The ID of the task to complete
 * @returns {boolean} True if task was updated (was not already completed), false otherwise
 */
function completeTask(taskId) {
    const tasks = loadTasks();
    const taskIndex = tasks.findIndex(t => t.id === taskId);

    if (taskIndex === -1) {
        logger.warn(`Task not found: ${taskId}`);
        return false;
    }

    if (tasks[taskIndex].completed) {
        return false; // Already completed
    }

    tasks[taskIndex].completed = true;
    tasks[taskIndex].completedAt = new Date().toISOString();

    // Logic specific to our flow:
    // If we complete saml-setup, let's auto-complete others if conditions meet? 
    // For now, keep it simple: explicit triggers.

    saveTasks(tasks);
    return true;
}

/**
 * Resets all tasks (for testing/demo)
 */
function resetTasks() {
    const tasks = loadTasks();
    tasks.forEach(t => {
        t.completed = false;
        t.completedAt = null;
    });
    saveTasks(tasks);
}

module.exports = {
    loadTasks,
    completeTask,
    resetTasks
};
