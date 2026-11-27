module.exports = function pad(str, len, ch = ' ') {
  str = String(str);
  return str.length >= len ? str : str + ch.repeat(len - str.length);
};
