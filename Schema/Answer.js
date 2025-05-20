import mongoose from "mongoose";

const answerSchema = mongoose.Schema({
  taskId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "lessons",
    required: true,
  },
  studentId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "users",
    required: true,
  },
  content: {
    type: String,
    required: true,
    default: ""
  },
  fileIds: [{
    type: mongoose.Schema.Types.ObjectId,
    ref: "attached_file",
    default: []
  }],
  grade_info: {
    grade: {
      type: Number,
      default: 0
    },
    maxGrade: {
      type: Number,
      default: 100
    }
  },
  feedback: String,
  status: {
    type: String,
    enum: ['awaiting', 'submitted', 'graded', 'rejected'],
    default: 'awaiting'
  },
  submittedAt: {
    type: Date,
    default: Date.now,
  },
  reviewedAt: {
    type: Date,
  }
});

export default mongoose.model("answers", answerSchema);
