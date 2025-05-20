import express from 'express';
import mongoose from "mongoose";
import Course from "./Cousre.js";
import Answer from "./Answer.js";
import Lesson from "./Lesson.js";
import Notification from "./Notification.js";
import Task from "./Task.js";


// Підключення до бази
await mongoose.connect("mongodb+srv://zirnzakf:YpBUGRxoakgLWO3z@education-app-website.oqxpu.mongodb.net/?retryWrites=true&w=majority&appName=education-app-website", {
  autoIndex: true
});



// Створюємо заглушки ID користувача, уроку тощо
// const fakeUserId = new mongoose.Types.ObjectId();
// const fakeStudentId = new mongoose.Types.ObjectId();
// const fakeCourseId = new mongoose.Types.ObjectId();
// const fakeLessonId = new mongoose.Types.ObjectId();
// const fakeTaskId = new mongoose.Types.ObjectId();

// Курси
await Course.create([
  {
    _id: "68164979a8fbb90df8513204",
    teacherId: "68176432b2cbccc366e8a0dd",
    title: "React Basics",
    description: "Курс для початківців з React",
    lessonsId: [], // ми додамо уроки після їх створення
    invitedUsers: ["68176359b2cbccc366e8a0d9"],
    status: "Published"
  },
  { teacherId: "68176432b2cbccc366e8a0dd", title: "Node.js API", description: "Build backends", status: "Draft", invitedUsers: ["68176359b2cbccc366e8a0d9"] },
]);

// Уроки
await Lesson.create([
  {
    courseId: new mongoose.Types.ObjectId("68164979a8fbb90df8513204"),
    title: "JSX & Components",
    content: "Learn JSX and React components basics",
    type: "lesson",
    videoUrl: "https://example.com/video1",
    duration: "20 хв"
  },
  {
    courseId: new mongoose.Types.ObjectId("68164979a8fbb90df8513204"),
    title: "Create your first component",
    content: "Practice creating React components",
    type: "task",
    duration: "30 хв"
  },
  {
    courseId: new mongoose.Types.ObjectId("68164979a8fbb90df8513204"),
    title: "React Hooks",
    content: "Learn useState and useEffect hooks",
    type: "lesson",
    videoUrl: "https://example.com/video2",
    duration: "25 хв"
  },
  {
    courseId: new mongoose.Types.ObjectId("68164979a8fbb90df8513204"),
    title: "Build counter with useState",
    content: "Implement counter using useState hook",
    type: "task",
    duration: "35 хв"
  }
]);
// Завдання
// await Task.create([
//   { _id: fakeTaskId, lessonId: fakeLessonId, title: "Build Todo App", description: "Create a simple todo app", deadline: new Date() },
// ]);

// Відповіді
// await Answer.create([
//   { taskId: fakeTaskId, studentId: fakeStudentId, content: "My solution", grade: 95, feedback: "Good job" },
// ]);

// Нотифікації
// await Notification.create([
//   { userId: fakeStudentId, type: "TaskAssigned", message: "You got new task", link: "/tasks", status: "SENT" },
// ]);

console.log("Test data inserted.");
process.exit();
