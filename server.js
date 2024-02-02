const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
// const cron = require("node-cron");
// const twilio = require("twilio");

const app = express();
const PORT = 5000;

const authMiddleware = require('./middleware/auth');

// Importing models
const SubTask = require("./models/subTask");
const User = require("./models/user");
const Task = require("./models/task");

app.use(bodyParser.json());

app.use('/api/tasks', authMiddleware);

mongoose
  .connect("mongodb://127.0.0.1:27017/taskManager")
  .then(() => {
    console.log("Connected to MongoDB");

    app.use((err, req, res, next) => {
      console.error(err.stack);
      res.status(500).send("Something went wrong!");
    });
  })
  .catch((error) => {
    console.error("Error connecting to MOongoDB", error);
  });

// cron.schedule("0 0 * * *", async () => {
//   try {
//     const tasksToUpdate = await Task.find({
//       due_date: { $lte: new Date() },
//       status: "TODO",
//     });

//     tasksToUpdate.forEach(async (task) => {
//       if (tasks.due_date < new Date()) {
//         task.priority = 0;
//       } else if (
//         task.due_date < new Date(new Date().setDate(new Date().getDate() + 2))
//       ) {
//         task.priority = 1;
//       } else if (
//         task.due_date < new Date(new Date().setDate(new Date().getDate() + 4))
//       ) {
//         task.priority = 2;
//       } else {
//         task.priority = 3;
//       }

//       await task.save();
//     });
//     console.log("Task priorities updated succesfully");
//   } catch (error) {
//     console.error("Error updating task priorities:", error);
//   }
// });

// cron.schedule("0 * * * *", async () => {
//   try {
//     const users = await User.find().sort({ priority: 1 }); //Sorting by priority

//     for (const user of users) {
//       const tasksToCall = await Task.find({
//         user_id: user.id,
//         due_date: { $lte: new Date() },
//         status: "TODO",
//       }).limit(1);

//       for (const task of tasksToCall) {
//         const phoneNumber = user.phone_number;
//         const taskTitle = task.title;

//         try {
//           await twilioClient.calls.create({
//             to: phoneNumber,
//             from: "phone_number",
//             url: "http://your-webhook-url/${task.id}",
//             method: "POST",
//           });

//           console.log(`Call made to ${phoneNumber} for task: ${taskTitle}`);
//         } catch (error) {
//           console.error(`Error making call to ${phoneNumber}`, error);
//         }
//       }
//     }
//   } catch (error) {
//     console.error("Error in Twilio call cron job:", error);
//   }
// });

// Import tasks router
const tasksRoutes = require('./routes/tasks');
app.use('/api/tasks', tasksRoutes);

// Import subTasks router
const subTasksRoutes = require('./routes/subTasks');
app.use('/api/subtasks', subTasksRoutes);

// Import users route
const usersRoutes = require('./routes/users');
app.use("/api/users", usersRoutes);


app.listen(PORT, () => {
  console.log(`Server is running on ${PORT}`);
});
