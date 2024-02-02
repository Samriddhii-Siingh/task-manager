const express = require("express");
const mongoose = require("mongoose");
const router = express.Router();
const Task = require("../models/task");

const authMiddleware = require("../middleware/auth");

// Create Task
router.post("/", authMiddleware, async (req, res) => {
  try {
    const { title, description, due_date } = req.body;
    const user = req.user; // from decoded JWT token

    if (!user || !user.userId) {
      console.error("Invalid user data in JWT:", user);
      return res.status(401).json({ error: "Invalid user data in JWT" });
    }

    const newTask = new Task({
      title,
      description,
      due_date,
      user_id: user.userId,
    });

    await newTask.validate();

    await newTask.save();

    return res
      .status(201)
      .json({ message: "Task created successfully", task: newTask });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Get all user tasks with filters and pagination
router.get("/", authMiddleware, async (req, res) => {
  try {
    const user = req.user;
    const { priority, due_date, page, pageSize } = req.query;

    let filters = { user_id: user.userId };

    // Apply filters based on user input
    if (priority !== undefined) {
      filters.priority = priority;
    }

    if (due_date !== undefined) {
      filters.due_date = { $lte: new Date(due_date) };
    }

    // Calculate skip and limit for pagination
    const skip = (page - 1) * pageSize;
    const limit = parseInt(pageSize);

    const tasks = await Task.find(filters)
      .sort({ due_date: 1 }) // Sorting in ascending order
      .skip(skip)
      .limit(limit);

    const totalTasksCount = await Task.countDocuments(filters);

    return res.status(200).json({ tasks, totalTasksCount });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal Server Error" });
  }
});

// Update task
router.put("/:taskId", authMiddleware, async (req, res) => {
  try {
    const { due_date, status } = req.body;

    // Check if status is valid
    if (status !== "TODO" && status !== "DONE") {
      return res.status(400).json({ error: "Invalid status. Status must be 'TODO' or 'DONE'" });
    }

    const updatedTask = await Task.findByIdAndUpdate(
      req.params.taskId,
      {
        due_date,
        status,
      },
      { new: true } // Return the updated task
    );

    if (!updatedTask) {
      return res.status.apply(404).json({ error: "Task not found" });
    }

    return res
      .status(200)
      .json({ message: "Task updated successfully", task: updatedTask });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
});

//Delete task
router.delete("/:taskId", authMiddleware, async (req, res) => {
  try {
    const deletedTask = await Task.findByIdAndUpdate(
      req.params.taskId,
      {
        deleted_at: new Date(),
      },
      { new: true }
    );

    if (!deletedTask) {
      return res.status(404).json({ error: "Task not found" });
    }

    return res
      .status(200)
      .json({ message: "Task deleted successfully", task: deletedTask });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal error server" });
  }
});

module.exports = router;
