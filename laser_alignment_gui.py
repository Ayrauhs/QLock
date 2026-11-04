# Along with PQC, ML-KEM-768, using laser for extra secure transmission
# Optical interlock: HSV filtering -> binary mask -> contour -> centroid (cx, cy) -> must sit on the target reticle.
# NOTE: a webcam cannot measure wavelength; this isolates a bright, saturated *red* spot (flashlights are
# white/low-saturation and are rejected). It is an operator-presence/alignment check, not a cryptographic proof.
import math

import cv2
import numpy as np


def run_alignment_hud(min_pixels=5, max_pixels=1500, tolerance_px=80, stable_frames=10, camera_index=0) -> bool:
    print("Launching Red Laser Alignment Algorithm...")
    cap = cv2.VideoCapture(camera_index)

    if not cap.isOpened():
        print("Error- Camera Initialization Failed")
        return False

    laser_aligned = False
    stable = 0

    try:
        while True:
            ret, frame = cap.read()
            if not ret:
                print("Error- Frame Capture Failed")
                break

            frame = cv2.flip(frame, 1)
            h, w, _ = frame.shape
            tx, ty = w // 2, h // 2  # target coordinates

            hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)

            lower_red1 = np.array([0, 120, 200])
            upper_red1 = np.array([10, 255, 255])
            mask1 = cv2.inRange(hsv, lower_red1, upper_red1)

            lower_red2 = np.array([170, 120, 200])
            upper_red2 = np.array([179, 255, 255])
            mask2 = cv2.inRange(hsv, lower_red2, upper_red2)

            bright_spots = cv2.bitwise_or(mask1, mask2)
            pixel_count = cv2.countNonZero(bright_spots)

            is_detected = min_pixels <= pixel_count <= max_pixels  # rejects dust-sized noise and big red areas
            on_target = False
            cx = cy = None

            if is_detected:
                contours, _ = cv2.findContours(bright_spots, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
                if contours:
                    largest_contour = max(contours, key=cv2.contourArea)
                    M = cv2.moments(largest_contour)
                    if M["m00"] > 0:
                        cx = int(M["m10"] / M["m00"])
                        cy = int(M["m01"] / M["m00"])
                        on_target = math.hypot(cx - tx, cy - ty) <= tolerance_px

                        spot_color = (0, 255, 0) if on_target else (0, 165, 255)
                        cv2.circle(frame, (cx, cy), 20, spot_color, 2)
                        cv2.line(frame, (cx - 30, cy), (cx + 30, cy), spot_color, 1)
                        cv2.line(frame, (cx, cy - 30), (cx, cy + 30), spot_color, 1)
                        cv2.putText(frame, f"LASER ({cx}, {cy})", (cx + 25, cy - 10),
                                    cv2.FONT_HERSHEY_SIMPLEX, 0.5, spot_color, 1)

            stable = stable + 1 if (is_detected and on_target) else 0
            is_locked = stable >= stable_frames

            cv2.circle(frame, (tx, ty), tolerance_px, (255, 255, 0), 1)  # target window
            cv2.drawMarker(frame, (tx, ty), (255, 255, 0), cv2.MARKER_CROSS, 20, 1)

            hud_color = (0, 255, 0) if is_locked else (0, 0, 255)
            if is_locked:
                status_text = "OPTICAL LINK: LOCKED"
            elif is_detected and not on_target:
                status_text = "OPTICAL LINK: OFF-TARGET"
            else:
                status_text = f"OPTICAL LINK: ALIGNING... ({stable}/{stable_frames})"

            cv2.rectangle(frame, (10, 10), (w - 10, 70), (20, 20, 20), -1)
            cv2.rectangle(frame, (10, 10), (w - 10, 70), hud_color, 2)
            cv2.putText(frame, f"STATUS: {status_text}", (25, 38),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, hud_color, 2)
            cv2.putText(frame, f"Signal Intensity: {pixel_count} px | Press [SPACE] to Confirm | [Q]/[ESC] to Abort",
                        (25, 58), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (220, 220, 220), 1)

            cv2.imshow("QLock - Optical Alignment HUD", frame)

            key = cv2.waitKey(1) & 0xFF
            if key == ord(' '):
                if is_locked:
                    laser_aligned = True
                    print("Laser alignment confirmed by operator.")
                    break
                else:
                    print("Cannot confirm: Laser optical link not locked on target!")
            elif key == ord('q') or key == 27:
                print("Alignment sequence cancelled by operator.")
                laser_aligned = False
                break
    finally:
        cap.release()
        cv2.destroyAllWindows()

    return laser_aligned


if __name__ == "__main__":
    run_alignment_hud()
