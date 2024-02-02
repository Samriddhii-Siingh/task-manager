const mongoose = require("mongoose");

const subTaskSchema = mongoose.Schema({
  task_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Task",
    required: true,
  },
  title: {
    type: String, // Include a title for the subtask
    required: true,
  },
  status: {
    type: Number,
    enum: [0, 1], // 0 - incomplete, 1 - complete
    required: true,
  },
  created_at: {
    type: Date,
    default: Date.now,
  },
  updated_at: {
    type: Date,
    default: null,
  },
  deleted_at: {
    type: Date,
    default: null,
  },
});



const SubTask = mongoose.model("SubTask", subTaskSchema);
module.exports = SubTask;
