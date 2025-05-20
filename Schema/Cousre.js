import mongoose from "mongoose";

const courseSchema = mongoose.Schema({

  teacherId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "users",
    required: true

  },
  title: {
    type: String,
    required: true
  },
  description: {
    type: String,
    maxlength: [300, 'Bio should not be more than 200'],
    default: "",
  },
  lessonsId: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "lessons", // Посилання на модель уроків
    default: []
  }],
  invitedUsers: [{  //  список запрошених користувачів
    type: mongoose.Schema.Types.ObjectId,
    ref: "users",
    default: ["68176359b2cbccc366e8a0d9"]
  }],
  inviteCode: {
    type: String,
  },
  status: {
    type: String,
    enum: ["Draft", "Published", "Archived"],
    default: "Draft"
  }
}, {
  timestamps: {
    createdAt: 'joinedAt'
  }

});

export default mongoose.model("courses", courseSchema);
