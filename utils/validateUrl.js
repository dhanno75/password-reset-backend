export const validUrl = (url) => {
  try {
    new URL(string);
    return true;
  } catch (err) {
    return false;
  }
};
