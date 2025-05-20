import express from 'express';
import mongoose, { model } from 'mongoose';
import 'dotenv/config'
import bcrypt from 'bcryptjs';
import { nanoid } from 'nanoid';
import jwt from 'jsonwebtoken';
import cors from 'cors';
import { OAuth2Client } from 'google-auth-library';
import cookieParser from 'cookie-parser';
import multer from 'multer';
import crypto from 'crypto';
import { uploadFile, deleteFile, getObjectSignedUrl } from './s3.config.js';

import User from './Schema/User.js';
import Course from "./Schema/Cousre.js";
import Answer from "./Schema/Answer.js";
import AttachedFile from './Schema/AttachedFile.js';
import Lesson from "./Schema/Lesson.js";






const server = express();
let PORT = 3000;

const storage = multer.memoryStorage();
const upload = multer({ storage });


let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // Шаблон для пошти
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // Шаблон для пароля




mongoose.connect(process.env.DB_LOCATION, {
  autoIndex: true
})

server.use(express.json());
server.use(cookieParser()); // Дописати колись
server.use(cors({
  origin: 'http://localhost:5173', // або твій реальний фронтовий домен
  credentials: true // дозволяє надсилати кукі між клієнтом і сервером
}));

const generateFileName = (bytes = 32) => crypto.randomBytes(bytes).toString('hex');



const generateUserID = async (email) => {

  let userEmailName = email.split("@")[0];

  let user_id_tpm = (userEmailName) => {
    let result = "";
    let tmp = userEmailName.split(".");
    for (let i = 0; i < tmp.length; i++) {
      result += tmp[i].replace(".");

    }
    console.log(result);
    return result;
  }

  let user_id = user_id_tpm(userEmailName);

  let isUsernameNoUnique = await User.exists({ "personal_info.user_id": user_id }).then((result) => result)

  isUsernameNoUnique ? user_id += nanoid().substring(0, 5) : "";
  return user_id;
}

const formatDatatoSend = (user) => {
  const access_token = jwt.sign({
    fullname: user.personal_info.fullname,
    user_id: user._id,
    profile_img: user.personal_info.profile_img,
    email: user.personal_info.email,
    role: user.personal_info.role
  }, process.env.SECRET_ACCESS_KEY, { expiresIn: "170h" });
  return {
    access_token,
    fullname: user.personal_info.fullname,
    user_id: user._id,
    profile_img: user.personal_info.profile_img,
    email: user.personal_info.email,
    role: user.personal_info.role
  }
}

const sentCookiesHttpOnly = (res, nameCookies, data) => {
  res.cookie(nameCookies, data, {
    httpOnly: true,           // ❗ браузер не зможе прочитати цей кукі через JS
    secure: false,            // true якщо ти на HTTPS (на проді)
    sameSite: "Lax",          // або "None" якщо HTTPS і хочеш крос-домен
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 днів
  });

  console.log(data)
}

const verifyJWT = (req, res, next) => {
  const token = req.cookies.access_token;

  if (!token) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  let decoded;
  try {
    decoded = jwt.verify(token, process.env.SECRET_ACCESS_KEY);
  } catch (error) {
    return res.status(401).json({ error: "Invalid token" });
  }
  req.decodedUser = decoded;

  next();

};

server.post('/auth-user', async (req, res) => {
  const token = req.cookies.access_token;
  console.log(token)

  if (!token) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    const decoded = jwt.verify(token, process.env.SECRET_ACCESS_KEY);

    return res.status(200).json({
      access_token: token,
      fullname: decoded.fullname,
      user_id: decoded.user_id,
      profile_img: decoded.profile_img,
      email: decoded.email,
      role: decoded.role
    });

  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
});

server.post('/api/auth/google', async (req, res) => {
  const { token } = req.body;

  try {
    const client = new OAuth2Client();
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { email, name, picture } = payload;

    console.log("✅ Google user verified:", { email, name, picture });

    let user = await User.findOne({ "personal_info.email": email });

    if (user) {
      if (!user.google_auth) {
        console.log("The user is already registered with this email, but not through Google")
        return res.status(403).json({ "error": "The user is already registered with this email, but not through Google" });
      } else {
        const datatoSend = formatDatatoSend(user)
        sentCookiesHttpOnly(res, "access_token", datatoSend.access_token)
        return res.status(200).json(datatoSend);
      }
    }

    // New Google user – create in DB
    const user_id = await generateUserID(email);

    const newUser = new User({
      personal_info: {
        fullname: name,
        email,
        profile_img: picture,
        user_id,
        password: '', // No password needed for Google
      },
      google_auth: true
    });

    const savedUser = await newUser.save();

    const datatoSend = formatDatatoSend(savedUser)
    sentCookiesHttpOnly(res, "access_token", datatoSend.access_token)
    return res.status(200).json(datatoSend);

  } catch (err) {
    console.error('❌ Google token verification failed:', err.message);
    return res.status(401).json({ error: 'Invalid Google token' });
  }
});


server.post("/signup", (req, res) => {
  let { fullname, email, password } = req.body;
  if (fullname.length < 3) {
    return res.status(403).json({ "error": "error min length 3" })
  }

  if (!email.length) {
    return res.status(403).json({ "error": "Enter email" })
  }
  if (!emailRegex.test(email)) {
    return res.status(403).json({ "error": "Email is invalid" })
  }
  if (!passwordRegex.test(password)) {
    return res.status(403).json({ "error": "Password should be 6 to 20 characters Kong with a numeric, 1 lowercase and 1 uppercase letters" })
  }

  bcrypt.hash(password, 10, (err, hashed_password) => {
    let user_id =
      console.log(hashed_password);
  })

  bcrypt.hash(password, 10, async (err, hashed_password) => {
    let user_id = await generateUserID(email);
    let user = new User({
      personal_info: {
        fullname, email, password: hashed_password, user_id
      }

    })
    user.save().then((u) => {

      const datatoSend = formatDatatoSend(u)
      sentCookiesHttpOnly(res, "access_token", datatoSend.access_token)
      return res.status(200).json(datatoSend);

    })
      .catch(err => {
        if (err.code === 11000) {
          return res.status(500).json({ "error": "Email already exist" })
        }
      })
  })


})

server.post("/signin", (req, res) => {

  let { email, password } = req.body;

  User.findOne({ "personal_info.email": email })
    .then((user) => {
      if (user == null) {
        return res.status(403).json({ "error": "Email not found" });
      }

      if (user.google_auth) {
        return res.status(403).json({ "error": "The user is already registered with this email, but through Google" });
      }

      bcrypt.compare(password, user.personal_info.password, (err, result) => {
        if (err) {
          return res.status(403).json({ "error": "Error occured while login please try again" });
        }

        if (!result) {
          return res.status(403).json({ "error": "Incorrect password" });
        } else {
          console.log(result);
          const datatoSend = formatDatatoSend(user)
          sentCookiesHttpOnly(res, "access_token", datatoSend.access_token)
          return res.status(200).json(datatoSend);

        }

      })

    })
    .catch(err => {
      console.log(err.message);
      return res.status(500).json({ "error": err.message })

    })

})

server.post('/logout', (req, res) => {
  res.clearCookie("access_token", {
    httpOnly: true,
    secure: false,
    sameSite: "Lax"
  });

  res.json({ message: "Вихід успішний" });
});


server.post('/user-courses', verifyJWT, async (req, res) => {
  try {
    const userId = req.decodedUser.user_id;

    // Курси, де користувач є в invitedUsers
    const invitedCourses = await Course.find({ invitedUsers: userId })

      .select("title description teacherId")

      .populate({
        path: 'teacherId',
        model: 'users',
        select: 'personal_info.fullname personal_info.profile_img'
      });

    // Курси, де користувач є викладачем
    const ownCourses = await Course.find({ teacherId: userId })
      .select("title description teacherId")
      .populate({
        path: 'teacherId',
        model: 'users',
        select: 'personal_info.fullname personal_info.profile_img'
      })
      .sort({ createdAt: -1 });

    // Об’єднуємо обидва масиви курсів (без дублікатів)
    const courseMap = new Map();

    [...invitedCourses, ...ownCourses].forEach(course => {
      courseMap.set(course._id.toString(), course);
    });

    const mergedCourses = Array.from(courseMap.values());

    res.status(200).json({
      courses: mergedCourses
    });

  } catch (error) {
    console.error('Помилка при отриманні курсів:', error);
    res.status(500).json({ error: "Внутрішня помилка сервера" });
  }
});


server.post('/course/lessons/:courseId', verifyJWT, async (req, res) => {
  // try {
  const userId = req.decodedUser.user_id;
  const courseId = req.params.courseId;

  const course = await Course.findById(courseId)
    .populate({
      path: 'lessonsId',
      options: { sort: { createdAt: -1 } }
    })
    .populate({
      path: 'teacherId',
      select: '_id personal_info.fullname personal_info.email personal_info.profile_img',
    });


  //  Перевірка: чи існує курс
  if (!course) {
    return res.status(404).json({ error: 'Course not found' });
  }

  //  Перевірка: чи має доступ
  const hasAccess =
    course.teacherId._id.toString() === userId ||
    course.invitedUsers.some(user => user.toString() === userId);

  if (!hasAccess) {
    return res.status(403).json({ error: 'Access denied' });
  }

  let userRole = "user"

  if (course.teacherId._id.toString() === userId) {
    userRole = "teacher"
  }


  return res.status(200).json({
    course: course,
    userRole: userRole
  });
});

server.post("/course/lesson/:id", verifyJWT, async (req, res) => {
  try {
    const userId = req.decodedUser.user_id;

    const lesson = await Lesson.findById(req.params.id);

    if (!lesson) {
      return res.status(404).json({ error: "Урок не знайдено" });
    }

    const course = await Course.findById(lesson.courseId)
      .populate({
        path: "teacherId",
        select: "_id personal_info.fullname personal_info.profile_img "
      });

    if (!course) {
      return res.status(404).json({ error: "Курс не знайдено" });
    }


    const hasAccess =
      course.teacherId._id.toString() === userId ||
      course.invitedUsers.some(user => user.toString() === userId);

    if (!hasAccess) {
      return res.status(403).json({ error: 'Access denied' });
    }
    let userRole = "user"

    if (course.teacherId._id.toString() === userId) {
      userRole = "teacher"
    }



    console.log(lesson)
    return res.status(200).json({
      lesson: lesson,
      userRole: userRole,
      teacherInfo: course.teacherId
    })
  } catch (err) {
    console.error("Помилка при отриманні уроку:", err);
    return res.status(500).json({ error: "Внутрішня помилка сервера" });
  }
});


server.post('/download/answerFile/:id', verifyJWT, upload.array('files', 10), async (req, res) => {
  try {
    const lessonId = req.params.id;
    const userId = req.decodedUser.user_id;

    const answerUser = await Answer.findOne({ taskId: lessonId, studentId: userId });
    if (answerUser?.fileIds) {
      const fileDocs = [];
      for (let file of req.files) {
        const storedName = generateFileName();
        const fileBuffer = file.buffer;

        await uploadFile(fileBuffer, storedName, file.mimetype);
        const url = await getObjectSignedUrl(storedName);



        const fileDoc = await AttachedFile.create({
          ownerId: answerUser._id,
          ownerModel: "answers",
          originalName: file.originalname,
          storedName,
          url
        });

        answerUser.fileIds.push(fileDoc._id);
      }
      await answerUser.save();
      return res.status(200).json({ message: "Answer submitted" });
    }


    const answer = await Answer.create({
      taskId: lessonId,
      studentId: userId,
      content: "Файлова відповідь",
      status: "awaiting"
    });

    const fileDocs = [];
    for (let file of req.files) {
      const storedName = generateFileName();
      const fileBuffer = file.buffer;

      await uploadFile(fileBuffer, storedName, file.mimetype);
      const url = await getObjectSignedUrl(storedName);



      const fileDoc = await AttachedFile.create({
        ownerId: answer._id,
        ownerModel: "answers",
        originalName: file.originalname,
        storedName,
        url
      });

      fileDocs.push(fileDoc._id);
    }

    answer.fileIds = fileDocs;
    await answer.save();

    return res.status(200).json({ message: "Answer submitted" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Failed to submit answer" });
  }
});

server.post('/pull/files/:id', verifyJWT, async (req, res) => {
  try {
    const lessonId = req.params.id;
    const { lessonType } = req.body;
    console.log("Тип уроку який запрошує файли: " + lessonType + " по id уроку/завдання " + lessonId)
    const userId = req.decodedUser.user_id;

    let response = null
    if (lessonType === "task") {
      response = await Answer.findOne({ taskId: lessonId, studentId: userId });
    } else {
      response = await Lesson.findById(lessonId);
    }

    if (!response) {
      console.log("В даного уроку/завдання нема прикріплених файлів ! ")
      return res.json([]);
    }

    const files = await AttachedFile.find({ ownerId: response._id });
    for (let file of files) {
      file.url = await getObjectSignedUrl(file.storedName);
    }
    console.log("Прикріплені файли уроку: " + files)
    return res.json(files);

  } catch (err) {
    console.log(err)
    return res.status(500).json({ error: "Поимлка під час отримання відповіді :" + err })
  }

});

server.delete('/delete/answerFile/:id', async (req, res) => {
  try {
    const file = await AttachedFile.findById(req.params.id);
    if (!file) return res.status(404).json({ error: "File not found" });

    await deleteFile(file.storedName);
    await AttachedFile.deleteOne({ _id: file._id });
    await Answer.updateOne(
      { _id: file.ownerId },
      { $pull: { fileIds: file._id } }
    );

    console.log("❌ file delete: " + file)

    res.json({ message: "File deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete file" });
  }
});


server.post('/course/create', verifyJWT, async (req, res) => {
  try {
    const { title, description } = req.body;
    const userId = req.decodedUser.user_id;

    if (!title || !description) {
      return res.status(400).json({ message: "Всі поля обов'язкові!" });
    }

    const newCourse = await Course.create({
      title,
      description,
      teacherId: userId,
      inviteCode: nanoid(24) // короткий унікальний код
    });

    const courseData = await Course.findById(newCourse._id)
      .populate({
        path: 'teacherId',
        model: 'users',
        select: 'personal_info.fullname personal_info.profile_img'
      });

    return res.status(201).json({ course: courseData });
  } catch (error) {
    console.error("Помилка створення курсу:", error);
    res.status(500).json({ message: "Помилка сервера" });
  }
});

server.post('/course/join/:code', verifyJWT, async (req, res) => {
  try {
    const code = req.params.code;
    const userId = req.decodedUser.user_id;

    const course = await Course.findOne({ inviteCode: code })
      .populate({
        path: 'teacherId',
        model: 'users',
        select: 'personal_info.fullname personal_info.profile_img'
      });


    if (!course) {
      return res.status(404).json({ message: "Курс з таким кодом не знайдено" });
    }

    // Якщо вже є в invitedUsers — не додаємо повторно
    if (course.invitedUsers.includes(userId) ||
      course.teacherId._id.toString() === userId) {
      return res.status(409).json({ message: "Ви вже приєднані до курсу: " + course.title });
    }


    course.invitedUsers.push(userId);
    await course.save();

    return res.status(200).json({ course });
  } catch (error) {
    console.error("Помилка приєднання до курсу:", error);
    res.status(500).json({ message: "Помилка сервера" });
  }
});

server.post('/lessons/create/:courseId', upload.array('files', 10), async (req, res) => {
  try {
    const courseId = req.params.courseId;
    const {
      type,
      title,
      description,
      youtubeLink,
      deadline,
    } = req.body;

    // 1. Створення уроку/завдання
    const newLesson = await Lesson.create({
      courseId,
      title,
      content: description,
      type,
      videoUrl: youtubeLink || null,
      deadline
    });

    const fileDocs = [];
    // 2. Якщо є файли і тип "lesson" — зберігаємо їх
    if (type === "lesson" && req.files && req.files.length > 0) {
      for (let file of req.files) {
        const storedName = generateFileName();
        const fileBuffer = file.buffer;

        await uploadFile(fileBuffer, storedName, file.mimetype);
        const url = await getObjectSignedUrl(storedName);

        const fileDoc = await AttachedFile.create({
          ownerId: newLesson._id,
          ownerModel: "lesson",
          originalName: file.originalname,
          storedName,
          url
        });

        fileDocs.push(fileDoc._id);
      }
      newLesson.attachedFileIds = fileDocs;
      await newLesson.save();
    }

    const course = await Course.findById(courseId)
    course.lessonsId.push(newLesson._id);
    await course.save();


    res.status(201).json({ message: "Урок/завдання успішно створено!" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Помилка при створенні уроку/завдання." });
  }
});

server.get('/courses/:courseId/invite-code/generate', async (req, res) => {
  try {
    const courseId = req.params.courseId;

    const course = await Course.findById(courseId);
    const newInviteCode = nanoid(24);
    course.inviteCode = newInviteCode;

    await course.save();
    console.log("Згенеровано новий код запрошення для курсу: " + course.title + ", код запрошення: " + newInviteCode)
    return res.status(200).json(newInviteCode);

  } catch (err) {
    console.log("Помилка під час генерування коду запрошення ! : " + err)
    return res.status(500).json("Помилка під час генерування коду запрошення !")
  }

});

server.get('/courses/:courseId/people', verifyJWT, async (req, res) => {
  const courseId = req.params.courseId;
  const userId = req.decodedUser.user_id;

  if (!mongoose.Types.ObjectId.isValid(courseId)) {
    return res.status(400).json({ error: "Невалідний ID курсу" });
  }

  try {
    const course = await Course.findById(courseId)
      .populate({
        path: "teacherId",
        select: "_id personal_info"
      })
      .populate({
        path: "invitedUsers",
        select: "_id personal_info"
      });

    if (!course) {
      return res.status(404).json({ error: "Курс не знайдено" });
    }
    console.log("Запрошуваний запис зі списком людей !" + course)

    if (course.teacherId._id.toString() !== userId) {
      return res.status(403);
    }



    const teacher = course.teacherId;
    const students = course.invitedUsers;

    res.json({ teacher, students });
  } catch (error) {
    console.error("Помилка при отриманні учасників курсу:", error);
    res.status(500).json({ error: "Помилка сервера" });
  }
});

server.get("/answer/my/:id", verifyJWT, async (req, res) => {
  const id = req.params.id;
  const userId = req.decodedUser.user_id;

  try {
    const answer = await Answer.findOne({
      taskId: id,
      studentId: userId
    });

    if (!answer) {
      return res.status(404).json({ message: "Відповідь не знайдена" });
    }

    res.json(answer);
  } catch (error) {
    console.error("Помилка при отриманні відповіді:", error);
    res.status(500).json({ message: "Серверна помилка" });
  }
});

server.post("/answer/my/:id/status/update", verifyJWT, async (req, res) => {
  const id = req.params.id;
  const { newStatus } = req.body;
  const userId = req.decodedUser.user_id;

  try {
    const answer = await Answer.findOne({
      taskId: id,
      studentId: userId
    });

    if (!answer) {
      const newAnswer = await Answer.create({
        taskId: id,
        studentId: userId,
        content: "Відповідь без контенту",
        status: newStatus
      });
      await newAnswer.save();
      return res.status(201).json(newAnswer);
    }
    answer.status = newStatus;
    await answer.save();

    return res.status(200).json(answer);
  } catch (error) {
    console.error("Помилка при отриманні відповіді:", error);
    res.status(500).json({ message: "Серверна помилка" });
  }
});

server.delete("/delete/lesson/:id", verifyJWT, async (req, res) => {
  try {
    const lessonId = req.params.id;
    const userId = req.decodedUser.user_id;

    const lesson = await Lesson.findById(lessonId);
    if (!lesson) {
      return res.status(404).json({ error: "Lesson not found" });
    }

    const course = await Course.findById(lesson.courseId);
    if (!course) {
      return res.status(404).json({ error: "Course not found" });
    }

    if (String(course.teacherId) !== userId) {
      return res.status(403).json({ error: "Access denied" });
    }

    // ====== Якщо тип "lesson" — видаляємо прикріплені файли як раніше ======
    if (lesson.type === "lesson") {
      if (lesson.attachedFileIds.length > 0) {
        const attachedFiles = await AttachedFile.find({ _id: { $in: lesson.attachedFileIds } });
        console.log(attachedFiles)

        for (const file of attachedFiles) {
          if (file.storedName) {
            try {
              await deleteFile(file.storedName);
            } catch (err) {
              console.error(`Помилка при видаленні файла з S3: ${file.fileName}`, err);
            }
          }
        }

        await AttachedFile.deleteMany({ _id: { $in: lesson.attachedFileIds } });
      }
    }

    // ====== Якщо тип "task" — видаляємо відповіді з файлами ======
    if (lesson.type === "task") {
      const answers = await Answer.find({ taskId: lesson._id });
      console.log(answers)

      for (const answer of answers) {
        // Якщо в відповіді є прикріплені файли
        if (answer.fileIds?.length > 0) {
          const attachedFiles = await AttachedFile.find({ _id: { $in: answer.fileIds } });

          // Видаляємо кожен файл із S3
          for (const file of attachedFiles) {
            if (file.storedName) {
              await deleteFile(file.storedName);
            }
          }

          // Видаляємо файли з бази
          await AttachedFile.deleteMany({ _id: { $in: answer.fileIds } });
        }

        // Видаляємо відповідь з бази
        await Answer.findByIdAndDelete(answer._id);
      }
    }


    // Видаляємо lessonId з курсу
    course.lessonsId = course.lessonsId.filter(id => String(id) !== lessonId);
    await course.save();

    // Видаляємо сам урок
    await Lesson.findByIdAndDelete(lessonId);

    res.status(200).json({ message: "Урок успішно видалено." });

  } catch (err) {
    console.error("Помилка видалення уроку:", err);
    res.status(500).json({ error: "Помилка сервера при видаленні уроку." });
  }
});

server.get("/answers/by-task/:lessonId", verifyJWT, async (req, res) => {
  try {
    const lessonId = req.params.lessonId;
    const userId = req.decodedUser.user_id;

    const lesson = await Lesson.findById(lessonId)
      .populate("courseId")

    if (!lesson) {
      return res.status(404).json({ error: "Course not found" })
    }
    console.log(lesson);

    if (lesson.courseId.teacherId.toString() !== userId) return res.status(403).json({ error: "Нема доступу" })

    const answers = await Answer.find({ taskId: lessonId })
      .populate({
        path: "studentId",
        select: "personal_info.fullname personal_info.profile_img"
      })
      .populate("fileIds");

    if (!answers || answers.length === 0) {
      return res.status(400).json({ error: "Answers not found" });
    }

    const answersWithFiles = await Promise.all(
      answers.map(async (answer) => {
        const signedFiles = await Promise.all(
          answer.fileIds.map(async (file) => {
            const url = await getObjectSignedUrl(file.storedName);
            console.log(url)
            return {
              ...file.toObject(),
              url: url
            };
          })
        );

        return {
          ...answer.toObject(),
          fileIds: signedFiles
        };
      })
    );

    return res.json(answersWithFiles);

  } catch (error) {
    console.error("Server error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

server.put("/answers/grade/:id", verifyJWT, async (req, res) => {
  try {
    const answerId = req.params.id;
    const { feedback,
      grade,
      maxGrade
    } = req.body
    const answer = await Answer.findById(answerId)
    if (!answer) {
      return res.status(404).json({ error: "Answer not found" })
    }

    answer.feedback = feedback;
    answer.grade_info.grade = grade;
    answer.grade_info.maxGrade = maxGrade;
    answer.status = "graded"
    await answer.save();
    console.log("Оцінено завдання: " + answer)
    return res.status(200).json(answer)

  } catch (error) {
    console.error("Server error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

server.put("/answers/reject/:id", verifyJWT, async (req, res) => {
  try {
    const answerId = req.params.id;
    const { feedback } = req.body

    const answer = await Answer.findById(answerId)
    if (!answer) {
      return res.status(404).json({ error: "Answer not found" })
    }

    answer.feedback = feedback;
    answer.status = "rejected"
    await answer.save();
    console.log("Повернуто завдання: " + answer)
    return res.status(200).json(answer)

  } catch (error) {
    console.error("Server error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});
server.put("/lesson/edit/:id", verifyJWT, async (req, res) => {
  try {
    const lessonId = req.params.id;
    const { title,
      content,
      urlVideo,
      deadline } = req.body

    const lesson = await Lesson.findById(lessonId)
    if (!lesson) {
      return res.status(404).json({ error: "Lesson not found" })
    }

    lesson.title = title;
    lesson.content = content;
    lesson.videoUrl = urlVideo;
    lesson.deadline = deadline;
    await lesson.save();
    console.log("Урок/Завдання було було оновлено: " + lesson)
    return res.status(200).json(lesson)

  } catch (error) {
    console.error("Server error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

server.delete("/courses/:courseId/people/:studentId/delete", verifyJWT, async (req, res) => {
  try {
    const courseId = req.params.courseId;
    const studentId = req.params.studentId;

    const course = await Course.findById(courseId);

    if (!course) {
      return res.status(404).json({ error: "Course not found" });
    }

    // Перевірка, чи користувач — вчитель курсу
    if (course.teacherId.toString() !== req.decodedUser.user_id) {
      return res.status(403).json({ error: "Access denied. Only the teacher can remove students." });
    }

    // Видаляємо студента
    course.invitedUsers = course.invitedUsers.filter(
      (id) => id.toString() !== studentId
    );

    await course.save();

    return res.status(200).json({ message: "Student removed successfully", students: course.invitedUsers });

  } catch (error) {
    console.error("Server error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
})

server.listen(PORT, () => {
  console.log('listening port ->' + PORT);
})