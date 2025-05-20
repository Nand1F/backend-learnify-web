import mongoose from "mongoose";

const lessonSchema = mongoose.Schema({
  courseId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "courses",
    required: true
  },
  title: {
    type: String,
    required: true
  },
  content: {
    type: String,
    required: true
  },
  type: {
    type: String,
    enum: ["lesson", "task"],
    default: "lesson",
    required: true
  },
  attachedFileIds: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "attached_file",
    default: []
  }],
  videoUrl: String,
  deadline: {
    type: Date,
  }
}, {
  timestamps: true
});

export default mongoose.model("lessons", lessonSchema);
