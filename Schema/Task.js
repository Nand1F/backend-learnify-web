import mongoose from "mongoose";

const taskSchema = mongoose.Schema({

  lessonId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "lessons",
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
  deadline: Date
}, {
  timestamps: {
    createdAt: 'joinedAt'
  }

});

export default mongoose.model("tasks", taskSchema);
