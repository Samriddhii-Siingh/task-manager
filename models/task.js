const mongoose = require("mongoose");

const taskSchema = mongoose.Schema({
  title: {
    type: String,
    required: true,
  },
  description: {
    type: String,
    required: true,
  },
  due_date: {
    type: Date,
    required: true,
  },
  user_id: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true,
  },
  priority: {
    type: Number,
    default: 0,
  },
  status: {
    type: String,
    enum: ["TODO", "IN_PROGRESS", "DONE"],
    required: true,
    default: "TODO",
  },
  deleted_at: {
    type: Date,
    default: null,
  },
});

taskSchema.pre('save', function(next) {
  // Calculate priority based on due_date
  const currentDate = new Date();
  const timeDifference = this.due_date - currentDate;
  const daysDifference = timeDifference / (1000 * 3600 * 24);

  if (daysDifference === 0) {
    this.priority = 0;
  } else if (daysDifference <= 2) {
    this.priority = 1;
  } else if (daysDifference <= 4) {
    this.priority = 2;
  } else {
    this.priority = 3;
  }

  next();
});


const Task = mongoose.model("Task", taskSchema);
module.exports = Task;
