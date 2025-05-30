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
import Notification from './Schema/Notification.js';
import { error, profile } from 'console';
import { config } from './config.js';



const server = express();
let PORT = process.env.PORT || 3000;

const storage = multer.memoryStorage();
const upload = multer({ storage });


let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
let passwordRegex = /^(?=.*\d)(?=.*[a-zа-яєіїґ])(?=.*[A-ZА-ЯЄІЇҐ]).{6,20}$/;

mongoose.connect(process.env.DB_LOCATION, {
  autoIndex: true
})

server.use(express.json());
server.use(cookieParser());
server.use(cors({
  origin: process.env.CORS_URL,
  credentials: true
}));

const adminAdd = async () => {
  const adminData = {
    personal_info: {
      fullname: "Головний Адмін",
      email: "admin@adm.com",
      password: "1234Ferd",
      user_id: "mainAdmin",
      profile_img: "",
      role: "admin",
    },
    google_auth: false,
  };

  const existingAdmin = await User.findOne({ "personal_info.email": adminData.personal_info.email });

  if (!existingAdmin) {
    // Хешуємо пароль
    bcrypt.hash(adminData.personal_info.password, 10, async (err, hashedPassword) => {
      if (err) {
        console.error("❌ Помилка при хешуванні паролю:", err);
        return;
      }

      adminData.personal_info.password = hashedPassword;

      const newAdmin = new User(adminData);
      await newAdmin.save();
      console.log("✅ Адміна створено!");
    });
  } else {
    console.log("⚠️ Адмін уже існує.");
  }
};

const generateFileName = (bytes = 32) => crypto.randomBytes(bytes).toString('hex');

const generateUserID = async (email) => {

  let userEmailName = email.split("@")[0];

  let user_id_tpm = (userEmailName) => {
    let result = "";
    let tmp = userEmailName.split(".");
    for (let i = 0; i < tmp.length; i++) {
      result += tmp[i].replace(".");

    }
    // console.log(result);
    return result;
  }

  let user_id = user_id_tpm(userEmailName);

  let isUsernameNoUnique = await User.exists({ "personal_info.user_id": user_id }).then((result) => result)

  isUsernameNoUnique ? user_id += nanoid().substring(0, 5) : "";
  return user_id;
}

const formatDatatoSend = async (user) => {
  const access_token = jwt.sign({
    fullname: user.personal_info.fullname,
    user_id: user._id,
    profile_img: user.personal_info.profile_img,
    email: user.personal_info.email,
    role: user.personal_info.role,
    user_avatar_type: user.user_avatar_type,
    isBlocked: user.isBlocked
  }, process.env.SECRET_ACCESS_KEY, { expiresIn: "170h" });
  return {
    access_token,
    fullname: user.personal_info.fullname,
    user_id: user._id,
    profile_img: await getAvatar(user),
    email: user.personal_info.email,
    role: user.personal_info.role,
    user_avatar_type: user.user_avatar_type,
    isBlocked: user.isBlocked
  }
}

const createCourseNotification = async (courseId, type, options) => {
  try {
    const course = await Course.findById(courseId);
    if (!course) throw new Error("Course not found");

    let title = '';
    let message = '';
    let link = options.link || `/course/lesson/${options.lessonId}`;

    switch (type) {
      case 'lesson_created':
        title = 'Новий урок';
        message = `До курсу "${course.title}" додано новий урок: "${options.lessonTitle}"`;
        break;

      case 'task_created':
        title = 'Нове завдання';
        message = `До курсу "${course.title}" додано нове завдання: "${options.lessonTitle}"`;
        break;

      case 'task_graded':
        title = 'Оцінка за завдання';
        message = `Ваше завдання "${options.lessonTitle}" у курсі "${course.title}" було оцінене`;
        break;

      case 'task_returned':
        title = 'Завдання повернено';
        message = `Ваше завдання "${options.lessonTitle}" у курсі "${course.title}" було повернено на доопрацювання`;
        break;

      default:
        throw new Error("Unknown notification type");
    }

    // 🔽 Якщо це оцінка або повернення – лише для одного юзера
    if (type === 'task_graded' || type === 'task_returned') {
      if (!options.userId) throw new Error("Missing userId for personal notification");

      await Notification.create({
        userId: options.userId,
        title,
        message,
        link,
      });

      console.log(`✅ 1 notification sent to user ${options.userId}`);
    } else {
      // 🔽 Для групових – усім запрошеним учням
      const courseWithUsers = await course.populate('invitedUsers');
      const notifications = courseWithUsers.invitedUsers.map(user => ({
        userId: user._id,
        title,
        message,
        link,
      }));

      await Notification.insertMany(notifications);
      console.log(`✅ ${notifications.length} notifications sent for course "${course.title}"`);
    }

  } catch (error) {
    throw new Error("Error create message:" + error);
    console.error("❌ Failed to create notifications:", error.message);
  }
};

const sentCookiesHttpOnly = (res, nameCookies, data) => {
  res.cookie(nameCookies, data, {
    httpOnly: true,
    secure: config.IS_DEV_ENV ? false : true,            // true якщо ти на HTTPS (на проді)
    sameSite: config.IS_DEV_ENV ? "Lax" : "None",          // або "None" якщо HTTPS і хочеш крос-домен
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 днів
  });

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

const isAdmin = (req, res, next) => {

  const userRole = req.decodedUser.role;

  if (!userRole === "admin") {
    return res.status(403).json({ error: "Access denied" })
  }

  req.userRole = req.decodedUser.role;

  next();
}

const deleteLesson = async ({ lessonId }) => {
  const lesson = await Lesson.findById(lessonId);
  if (!lesson) throw { status: 404, message: "Lesson not found" };

  const course = await Course.findById(lesson.courseId);
  if (!course) throw { status: 404, message: "Course not found" };

  if (lesson.type === "lesson" && lesson.attachedFileIds.length > 0) {
    const attachedFiles = await AttachedFile.find({ _id: { $in: lesson.attachedFileIds } });

    for (const file of attachedFiles) {
      if (file.storedName) {
        try {
          await deleteFile(file.storedName);
        } catch (err) {
          console.error(`Error delete file: ${file.fileName}`, err);
        }
      }
    }

    await AttachedFile.deleteMany({ _id: { $in: lesson.attachedFileIds } });
  }

  if (lesson.type === "task") {
    const answers = await Answer.find({ taskId: lesson._id });

    for (const answer of answers) {
      if (answer.fileIds?.length > 0) {
        const attachedFiles = await AttachedFile.find({ _id: { $in: answer.fileIds } });

        for (const file of attachedFiles) {
          if (file.storedName) {
            await deleteFile(file.storedName);
          }
        }

        await AttachedFile.deleteMany({ _id: { $in: answer.fileIds } });
      }

      await Answer.findByIdAndDelete(answer._id);
    }
  }

  course.lessonsId = course.lessonsId.filter(id => String(id) !== lessonId);
  await course.save();
  await Lesson.findByIdAndDelete(lessonId);
  return { message: "Lesson delete" };
};

const deleteCourse = async ({ courseId }) => {
  const course = await Course.findById(courseId);
  if (!course) throw { status: 404, message: "Course not found" };

  for (const lessonId of course.lessonsId) {
    try {
      await deleteLesson({ lessonId: lessonId.toString() });
    } catch (err) {
      console.error(`Помилка при видаленні уроку ${lessonId}:`, err);
    }
  }

  await Course.findByIdAndDelete(courseId);
  return { message: "Course delete" };
};

const getAvatar = async (user) => {
  console.log(user)
  const type = user.user_avatar_type;

  if (type === "default") {
    return null;
  }
  if (type === "google") {
    return user?.personal_info?.profile_img ?? user?.profile_img ?? null;
  }

  if (type === "custom") {
    const file = await AttachedFile.findOne({
      ownerId: user._id || user.user_id,
      ownerModel: "users"
    });

    if (!file || !file.storedName) {
      return null;
    }
    const url = await getObjectSignedUrl(file.storedName);
    return url;
  }

  return null;
};

server.post('/auth-user', async (req, res) => {
  const token = req.cookies.access_token;

  if (!token) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  try {
    const decoded = jwt.verify(token, process.env.SECRET_ACCESS_KEY);

    return res.status(200).json({
      access_token: token,
      fullname: decoded.fullname,
      user_id: decoded.user_id,
      profile_img: await getAvatar(decoded),
      email: decoded.email,
      role: decoded.role,
      user_avatar_type: decoded.user_avatar_type,
      isBlocked: decoded.isBlocked
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
        const datatoSend = await formatDatatoSend(user)
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
      google_auth: true,
      user_avatar_type: "google"
    });

    const savedUser = await newUser.save();
    const datatoSend = await formatDatatoSend(savedUser)
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
    return res.status(405).json({ "error": "Password should be 6 to 20 characters Kong with a numeric, 1 lowercase and 1 uppercase letters" })
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
    user.save().then(async (u) => {

      const datatoSend = await formatDatatoSend(u)
      sentCookiesHttpOnly(res, "access_token", datatoSend.access_token)
      return res.status(200).json(datatoSend);

    })
      .catch(err => {
        if (err.code === 11000) {
          return res.status(409).json({ "error": "Email already exist" })
        }
      })
  })


})

server.post("/signin", async (req, res) => {

  let { email, password } = req.body;

  User.findOne({ "personal_info.email": email })
    .then((user) => {
      if (user == null) {
        return res.status(404).json({ "error": "Email not found" });
      }

      if (user.google_auth) {
        return res.status(410).json({ "error": "The user is already registered with this email, but through Google" });
      }

      bcrypt.compare(password, user.personal_info.password, async (err, result) => {
        if (err) {
          return res.status(403).json({ "error": "Error occured while login please try again" });
        }

        if (!result) {
          return res.status(404).json({ "error": "Incorrect password" });
        } else {
          // console.log(result);
          const datatoSend = await formatDatatoSend(user)
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

  res.json({ message: "ok" });
});

server.post('/user-courses', verifyJWT, async (req, res) => {
  try {
    const userId = req.decodedUser.user_id;
    const invitedCourses = await Course.find({ invitedUsers: userId })

      .select("title description teacherId")

      .populate({
        path: 'teacherId',
        model: 'users',
        select: 'personal_info.fullname personal_info.profile_img user_avatar_type'
      });

    for (const course of invitedCourses) {
      course.teacherId.personal_info.profile_img = await getAvatar(course.teacherId);
    }


    const ownCourses = await Course.find({ teacherId: userId })
      .select("title description teacherId")
      .populate({
        path: 'teacherId',
        model: 'users',
        select: 'personal_info.fullname personal_info.profile_img user_avatar_type'
      })
      .sort({ createdAt: -1 });

    const avatarCache = new Map(); // Кеш для збереження avatarUrl

    for (const course of ownCourses) {
      const teacherId = course.teacherId._id.toString();
      if (!avatarCache.has(teacherId)) {
        const avatarUrl = await getAvatar(course.teacherId);
        avatarCache.set(teacherId, avatarUrl);
      }

      course.teacherId.personal_info.profile_img = avatarCache.get(teacherId);
    }


    const courseMap = new Map();

    [...invitedCourses, ...ownCourses].forEach(course => {
      courseMap.set(course._id.toString(), course);
    });

    const mergedCourses = Array.from(courseMap.values());

    res.status(200).json({
      courses: mergedCourses
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
  }
});

server.post('/course/lessons/:courseId', verifyJWT, async (req, res) => {
  const userId = req.decodedUser.user_id;
  const courseId = req.params.courseId;
  const isAdmin = req.decodedUser.role === "admin" ? true : false;

  const course = await Course.findById(courseId)
    .populate({
      path: 'lessonsId',
      options: { sort: { createdAt: -1 } }
    })
    .populate({
      path: 'teacherId',
      select: '_id personal_info.fullname personal_info.email personal_info.profile_img user_avatar_type',
    });

  course.teacherId.personal_info.profile_img = await getAvatar(course.teacherId)



  if (!course) {
    return res.status(404).json({ error: 'Course not found' });
  }

  if (!isAdmin) {
    const hasAccess =
      course.teacherId._id.toString() === userId ||
      course.invitedUsers.some(user => user.toString() === userId);

    if (!hasAccess) {
      return res.status(403).json({ error: 'Access denied' });
    }
  }



  let userRole = "user"

  if (isAdmin) {
    userRole = "teacher"
  } else {
    if (course.teacherId._id.toString() === userId) {
      userRole = "teacher"
    }
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
    const isAdmin = req.decodedUser.role === "admin" ? true : false;

    if (!lesson) {
      return res.status(404).json({ error: "Урок не знайдено" });
    }

    const course = await Course.findById(lesson.courseId)
      .populate({
        path: "teacherId",
        select: "_id personal_info.fullname personal_info.profile_img user_avatar_type"
      });

    if (!course) {
      return res.status(404).json({ error: "Course not found" });
    }

    course.teacherId.personal_info.profile_img = await getAvatar(course.teacherId)



    if (!isAdmin) {
      const hasAccess =
        course.teacherId._id.toString() === userId ||
        course.invitedUsers.some(user => user.toString() === userId);

      if (!hasAccess) {
        return res.status(403).json({ error: 'Access denied' });
      }
    }

    let userRole = "user"

    if (isAdmin) {
      userRole = "teacher"
    } else {
      if (course.teacherId._id.toString() === userId) {
        userRole = "teacher"
      }
    }



    // console.log(lesson)
    return res.status(200).json({
      lesson: lesson,
      userRole: userRole,
      teacherInfo: course.teacherId
    })
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
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

        const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');

        const fileDoc = await AttachedFile.create({
          ownerId: answerUser._id,
          ownerModel: "answers",
          originalName: originalName,
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

      const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');

      const fileDoc = await AttachedFile.create({
        ownerId: answer._id,
        ownerModel: "answers",
        originalName: originalName,
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
    const userId = req.decodedUser.user_id;

    let response = null
    if (lessonType === "task") {
      response = await Answer.findOne({ taskId: lessonId, studentId: userId });
    } else {
      response = await Lesson.findById(lessonId);
    }

    if (!response) {
      return res.json([]);
    }

    const files = await AttachedFile.find({ ownerId: response._id });
    for (let file of files) {
      file.url = await getObjectSignedUrl(file.storedName);
    }
    return res.json(files);

  } catch (err) {
    console.log(err)
    return res.status(500).json({ error: "Server error" + err })
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
        select: 'personal_info.fullname personal_info.profile_img user_avatar_type'
      });

    courseData.teacherId.personal_info.profile_img = await getAvatar(courseData.teacherId)

    return res.status(201).json({ course: courseData });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
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
        select: 'personal_info.fullname personal_info.profile_img user_avatar_type'
      });


    if (!course) {
      return res.status(404).json({ message: "Course not found" });
    }

    course.teacherId.personal_info.profile_img = await getAvatar(course.teacherId)

    // Якщо вже є в invitedUsers — не додаємо повторно
    if (course.invitedUsers.includes(userId) ||
      course.teacherId._id.toString() === userId) {
      return res.status(409).json({ message: "You are already enrolled in the course: " + course.title });
    }


    course.invitedUsers.push(userId);
    await course.save();

    return res.status(200).json({ course });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
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

        const originalName = Buffer.from(file.originalname, 'latin1').toString('utf8');


        const fileDoc = await AttachedFile.create({
          ownerId: newLesson._id,
          ownerModel: "lesson",
          originalName: originalName,
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
    if (type === "lesson") {
      await createCourseNotification(courseId, 'lesson_created', {
        lessonId: newLesson._id,
        lessonTitle: newLesson.title
      });
    } else {
      await createCourseNotification(courseId, 'task_created', {
        lessonId: newLesson._id,
        lessonTitle: newLesson.title
      });
    }



    res.status(201).json({ message: "Lesson create" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err });
  }
});

server.get('/courses/:courseId/invite-code/generate', async (req, res) => {
  try {
    const courseId = req.params.courseId;

    const course = await Course.findById(courseId);
    const newInviteCode = nanoid(24);
    course.inviteCode = newInviteCode;

    await course.save();
    return res.status(200).json(newInviteCode);

  } catch (err) {
    console.error(err)
    return res.status(500).json("Server error")
  }

});

server.get('/courses/:courseId/people', verifyJWT, async (req, res) => {
  const courseId = req.params.courseId;
  const userId = req.decodedUser.user_id;

  const isAdmin = req.decodedUser.role === "admin" ? true : false;

  if (!mongoose.Types.ObjectId.isValid(courseId)) {
    return res.status(400).json({ error: "Invalide course ID" });
  }

  try {
    const course = await Course.findById(courseId)
      .populate({
        path: "teacherId",
        select: "_id personal_info user_avatar_type"
      })
      .populate({
        path: "invitedUsers",
        select: "_id personal_info user_avatar_type"
      });

    if (!course) {
      return res.status(404).json({ error: "Курс не знайдено" });
    }

    if (!isAdmin) {
      if (course.teacherId._id.toString() !== userId) {
        return res.status(403);
      }
    }




    const teacher = course.teacherId;

    teacher.personal_info.profile_img = await getAvatar(teacher)
    const students = course.invitedUsers;
    console.log(students)
    for (const student of students) {
      student.personal_info.profile_img = await getAvatar(student);
    }

    res.json({ teacher, students });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Server error" });
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
      return res.status(404).json({ message: "Answer not found" });
    }

    res.json(answer);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
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
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

server.delete("/delete/lesson/:id", verifyJWT, async (req, res) => {
  try {
    const lessonId = req.params.id;
    const userId = req.decodedUser.user_id;

    const isAdmin = req.decodedUser.role === "admin" ? true : false;

    const lesson = await Lesson.findById(lessonId);
    if (!lesson) {
      return res.status(404).json({ error: "Lesson not found" });
    }

    if (!isAdmin) {
      const course = await Course.findById(lesson.courseId);
      if (!course) {
        return res.status(404).json({ error: "Course not found" });
      }

      if (String(course.teacherId) !== userId) {
        return res.status(403).json({ error: "Access denied" });
      }
    }
    const result = await deleteLesson({ lessonId });

    res.status(200).json({ result });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

server.get("/answers/by-task/:lessonId", verifyJWT, async (req, res) => {
  try {
    const lessonId = req.params.lessonId;
    const userId = req.decodedUser.user_id;

    const isAdmin = req.decodedUser.role === "admin" ? true : false;

    const lesson = await Lesson.findById(lessonId)
      .populate("courseId")

    if (!lesson) {
      return res.status(404).json({ error: "Course not found" })
    }

    if (!isAdmin) {
      if (lesson.courseId.teacherId.toString() !== userId) return res.status(403).json({ error: "Acces denied" })
    }


    const answers = await Answer.find({ taskId: lessonId })
      .populate({
        path: "studentId",
        select: "personal_info.fullname personal_info.profile_img user_avatar_type"
      })
      .populate("fileIds");

    if (!answers || answers.length === 0) {
      return res.status(400).json({ error: "Answers not found" });
    }

    for (const answer of answers) {
      answer.studentId.personal_info.profile_img = await getAvatar(answer.studentId);
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

server.delete("/delete/course/:id", verifyJWT, async (req, res) => {
  try {
    const courseId = req.params.id;
    const userId = req.decodedUser.user_id;
    const isAdmin = req.decodedUser.role === "admin";

    const course = await Course.findById(courseId);
    if (!course) {
      return res.status(404).json({ error: "Course not found" });
    }

    if (!isAdmin && String(course.teacherId) !== userId) {
      return res.status(403).json({ error: "Access denied" });
    }

    const result = await deleteCourse({ courseId });
    res.status(200).json(result);
  } catch (err) {
    console.error(err);
    res.status(err.status || 500).json({ error: err.message || "Server error" });
  }
});

server.put("/answers/grade/:id", verifyJWT, async (req, res) => {
  try {
    const answerId = req.params.id;
    const { feedback,
      grade,
      maxGrade,
      courseId,
      lessonId
    } = req.body
    const answer = await Answer.findById(answerId)
      .populate({
        path: "studentId",
        select: "_id"
      })
    if (!answer) {
      return res.status(404).json({ error: "Answer not found" })
    }

    answer.feedback = feedback;
    answer.grade_info.grade = grade;
    answer.grade_info.maxGrade = maxGrade;
    answer.status = "graded"
    await answer.save();

    const lesson = await Lesson.findById(lessonId);

    if (!lesson) return res.status(404).json({ error: "Lesson not found but answer was graded " })

    await createCourseNotification(courseId, 'task_graded', {
      userId: answer.studentId._id,
      lessonId: lessonId,
      lessonTitle: lesson.title
    });

    return res.status(200).json(answer)

  } catch (error) {
    console.error("Server error:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

server.put("/answers/reject/:id", verifyJWT, async (req, res) => {
  try {
    const answerId = req.params.id;
    const { feedback,
      courseId,
      lessonId
    } = req.body

    const answer = await Answer.findById(answerId)
      .populate({
        path: "studentId",
        select: "_id"
      })
    if (!answer) {
      return res.status(404).json({ error: "Answer not found" })
    }

    answer.feedback = feedback;
    answer.status = "rejected"
    await answer.save();

    const lesson = await Lesson.findById(lessonId);
    if (!lesson) return res.status(404).json({ error: "Lesson not found, but answer was returned" })

    await createCourseNotification(courseId, 'task_returned', {
      userId: answer.studentId._id,
      lessonId: lessonId,
      lessonTitle: lesson.title
    });
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
    const isAdmin = req.decodedUser.role === "admin" ? true : false;
    const course = await Course.findById(courseId);

    if (!course) {
      return res.status(404).json({ error: "Course not found" });
    }


    if (!isAdmin) {
      if (course.teacherId.toString() !== req.decodedUser.user_id) {
        return res.status(403).json({ error: "Access denied. Only the teacher can remove students." });
      }
    }


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

server.get("/notifications/", verifyJWT, async (req, res) => {
  const userId = req.decodedUser.user_id;
  const skip = parseInt(req.query.skip) || 0;
  const limit = parseInt(req.query.limit) || 10;

  try {
    const notifications = await Notification.find({ userId })
      .sort({ createdAt: -1 }) // нові спочатку
      .skip(skip)
      .limit(limit);

    if (!notifications.length) {
      return res.status(404).json({ error: "Notifications not found" })
    }

    const total = await Notification.countDocuments({ userId });

    res.json({
      notifications,
      hasMore: skip + limit < total,
    });
  } catch (err) {
    console.error(err)
    res.status(500).json({ error: "Server error" });
  }
});

server.post("/notifications/read", async (req, res) => {
  const { ids } = req.body;

  try {
    await Notification.updateMany(
      { _id: { $in: ids } },
      { $set: { isRead: true } }
    );

    return res.status(200).json({ message: "Notifications marked as read" });
  } catch (error) {
    console.error("Error marking notifications as read:", error);
    return res.status(500).json({ message: "Server error" });
  }
});

server.get("/notifications/unread-count", verifyJWT, async (req, res) => {
  const unreadCount = await Notification.countDocuments({
    userId: req.decodedUser.user_id,
    isRead: false
  });

  res.json({ unreadCount });
});

server.get("/profile/get/:userId", verifyJWT, async (req, res) => {
  try {
    const userId = req.params.userId;

    const user = await User.findById(userId)
      .select("personal_info.fullname personal_info.user_id personal_info.bio personal_info.profile_img personal_info.role personal_info.email google_auth user_avatar_type");

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    const ownPage = userId === req.decodedUser.user_id;

    let coursesAsStudent = 0;
    let coursesAsTeacher = 0;
    let allCourses = 0;

    coursesAsStudent = await Course.countDocuments({ invitedUsers: user._id });
    coursesAsTeacher = await Course.countDocuments({ teacherId: user._id });
    allCourses = coursesAsStudent + coursesAsTeacher;

    const userObj = user.toObject();
    const avatarUrl = await getAvatar(user);
    userObj.personal_info.profile_img = avatarUrl;
    userObj.allCourses = allCourses;
    userObj.coursesAsStudent = coursesAsStudent;
    userObj.coursesAsTeache = coursesAsTeacher;
    return res.status(200).json({
      userData: userObj,
      ownPage
    });
  } catch (error) {
    console.error("Error fetching profile:", error);
    return res.status(500).json({ error: "Server error" });
  }
});

server.post('/profile/upload-avatar', verifyJWT, upload.single('avatar'), async (req, res) => {
  try {
    const userId = req.decodedUser.user_id;
    const file = req.file;

    if (!file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!allowedTypes.includes(file.mimetype)) {
      return res.status(400).json({ error: 'Invalid file type' });
    }

    if (file.size > 10 * 1024 * 1024) {
      return res.status(400).json({ error: 'File too large' });
    }

    const fileName = `avatars/${userId}_${Date.now()}.${file.mimetype.split('/')[1]}`;
    await uploadFile(file.buffer, fileName, file.mimetype);
    const url = await getObjectSignedUrl(fileName);
    const fileAvatar = await AttachedFile.findOne({ ownerId: userId, ownerModel: "users" })

    if (!fileAvatar) {
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).find({ error: "User not found" })
      }

      const avatarFile = await AttachedFile.create({
        ownerId: userId,
        ownerModel: "users",
        originalName: file.originalname,
        storedName: fileName,
        url: url
      });

      if (!avatarFile) {
        return res.status(404).json({ error: "Avatar not found" })
      }

      user.user_avatar_type = "custom";
      await user.save();
    } else {
      const user = await User.findById(userId);
      if (!user) {
        return res.status(404).find({ error: "User not found" })
      }

      await deleteFile(fileAvatar.storedName);

      fileAvatar.storedName = fileName;
      fileAvatar.originalName = file.originalname,
        fileAvatar.url = url;

      await fileAvatar.save();

      user.user_avatar_type = "custom";
      await user.save();
    }
    return res.status(200).json({ url });
  } catch (error) {
    console.error(error)
    res.status(500).json({ error: error })
  }
});

server.put("/profile/update/:userId", verifyJWT, async (req, res) => {
  try {
    const userId = req.params.userId;
    const verifyUserId = req.decodedUser.user_id;
    const { personal_info } = req.body;
    console.log(personal_info);
    if (userId !== verifyUserId) return res.status(403).json({ error: "Access denied" })

    const user = await User.findById(userId);
    user.personal_info.fullname = personal_info.fullname;
    user.personal_info.bio = personal_info.bio;
    await user.save();
    return res.status(200).json({ message: "Profile updated successfully" });
  } catch (error) {
    return res.status(500).json({ error: error })
  }

})

server.post("/profile/update-password/:userId", verifyJWT, async (req, res) => {
  try {
    const userId = req.params.userId;
    const verifyUserId = req.decodedUser.user_id;
    const { passwords } = req.body;

    if (userId !== verifyUserId) {
      return res.status(403).json({ error: "Access denied" });
    }

    if (!passwordRegex.test(passwords.new)) {
      return res.status(400).json({ "error": "Password should be 6 to 20 characters Kong with a numeric, 1 lowercase and 1 uppercase letters" })
    }

    const user = await User.findById(userId);
    const match = await bcrypt.compare(passwords.old, user.personal_info.password);

    if (!match) {
      console.log("Неправильний пароль");
      return res.status(409).json({ error: "Incorrect password entered!" });
    }

    const hashed_password = await bcrypt.hash(passwords.new, 10);
    user.personal_info.password = hashed_password;
    await user.save();

    console.log("Пароль було оновлено!");
    return res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

server.put("/user/avatar-type/:userId", verifyJWT, async (req, res) => {
  try {
    const { userId } = req.params;
    const { type } = req.body;

    if (userId !== req.decodedUser.user_id) {
      return res.status(403).json({ error: "Access denied" });
    }

    const user = await User.findById(userId);
    if (!user) return res.status(404).json({ error: "User not found" });

    user.user_avatar_type = type;
    await user.save();
    return res.status(200).json({ message: "Avatar type updated", type, profile_img: user.personal_info.profile_img });
  } catch (err) {
    return res.status(500).json({ error: "Server error" });
  }
});

server.get("/admin/users", verifyJWT, isAdmin, async (req, res) => {
  const userAdminId = req.decodedUser.user_id;
  const skip = parseInt(req.query.skip) || 0;
  const limit = parseInt(req.query.limit) || 10;

  const adminInfo = await User.findById(userAdminId)
    .select("personal_info.fullname personal_info.email")

  try {
    const users = await User.find({}, {
      "personal_info.fullname": 1,
      "personal_info.email": 1,
      "personal_info.role": 1,
      "isBlocked": 1,
      "_id": 1,
      "joinedAt": 1
    }).sort({ joinedAt: -1 })
      .skip(skip)
      .limit(limit);

    const total = await User.countDocuments();

    res.status(200).json({
      users: users,
      userAdmin: adminInfo || null,
      hasMore: skip + limit < total,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

server.patch('/admin/users/:id', verifyJWT, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { makeAdmin } = req.body;

  try {
    const updatedUser = await User.findByIdAndUpdate(id, { 'personal_info.role': makeAdmin ? 'admin' : 'user' }, { new: true });
    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }
    return res.status(200).json({ message: "Successful update" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

server.patch('/admin/blocked/:id', verifyJWT, isAdmin, async (req, res) => {
  const { id } = req.params;
  const { isBlocked } = req.body;

  try {
    const updatedUser = await User.findByIdAndUpdate(id, { isBlocked: isBlocked }, { new: true });
    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }
    return res.status(200).json({ message: `Successful update` });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

server.delete("/admin/user/:id", verifyJWT, isAdmin, async (req, res) => {
  try {
    const userId = req.params.id;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }
    const teacherCourses = await Course.find({ teacherId: userId });
    for (const course of teacherCourses) {
      await deleteCourse({ courseId: course._id });
    }
    await Notification.deleteMany({ userId });
    await User.findByIdAndDelete(userId);
    res.status(200).json({ message: "User and all related data successfully deleted." });
  } catch (err) {
    console.error("Error deleting user:", err);
    res.status(500).json({ error: "Server error while deleting user." });
  }
});

server.get("/admin/courses", verifyJWT, isAdmin, async (req, res) => {
  try {
    const skip = parseInt(req.query.skip) || 0;
    const limit = parseInt(req.query.limit) || 10;

    const courses = await Course.find({})
      .populate({
        path: "teacherId",
        select: "_id personal_info.fullname personal_info.email"
      })
      .skip(skip)
      .limit(limit)


    const total = await Course.countDocuments();


    res.status(200).json({
      courses,
      hasMore: skip + limit < total
    });
  } catch (err) {
    console.error("Server error", err);
    res.status(500).json({ message: "Server error" });
  }
});

server.delete("/admin/course/:id", verifyJWT, isAdmin, async (req, res) => {
  try {
    const courseId = req.params.id;

    const course = await Course.findById(courseId);
    if (!course) {
      return res.status(404).json({ error: "Course not found" });
    }
    await deleteCourse({ courseId });
    res.status(200).json({ message: "Course successfully deleted" });
  } catch (err) {
    console.error("Error while deleting course:", err);
    res.status(500).json({ message: "Server error while deleting course" });
  }
});




server.listen(PORT, () => {
  console.log('listening port ->' + PORT);
  adminAdd()
})