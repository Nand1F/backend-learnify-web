import mongoose from "mongoose";

const notificationSchema = mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "users",
        required: true
    },
    title: String,
    message: String,
    link: String,
    isRead: {
        type: Boolean,
        default: false
    },

}, {
    timestamps: true
});

export default mongoose.model("notifications", notificationSchema);
