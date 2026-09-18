/**
 * The image source for a 2FA QR code.
 *
 * `setupTwoFactor.qrCodePng` is BARE base64 of a PNG (no `data:` prefix): used
 * directly as `<img src>` the browser resolves it as a relative URL and the
 * image never renders. A value that is already a data URL is passed through,
 * so a future server that sends one cannot break the image again.
 */
export function qrCodeImageSrc(png: string): string {
  return png.startsWith("data:") ? png : `data:image/png;base64,${png}`;
}
