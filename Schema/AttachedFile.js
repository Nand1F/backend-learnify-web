import mongoose from "mongoose";

const AttachedFileSchema = mongoose.Schema({
  ownerId: {
    type: mongoose.Schema.Types.ObjectId,
    required: true,
    refPath: 'ownerModel'
  },
  ownerModel: {
    type: String,
    required: true,
    enum: ['answers', 'lesson', 'users']
  },
  originalName: {
    type: String,
    required: true
  },
  storedName: {
    type: String,
    required: true
  },
  url: {
    type: String,
    required: true
  },
  uploadedAt: {
    type: Date,
    default: Date.now
  }
});

export default mongoose.model("attached_file", AttachedFileSchema);
