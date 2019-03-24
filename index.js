const bcrypt = require('bcryptjs')

const plugin = (schema, {
  saltWorkFactor = 10,
  propertyName = 'password',
  methodName = 'comparePassword'
} = {}) => {
  schema.add({
    [propertyName]: {
      type: String,
      required: true
    }
  })

  schema.pre('save', async function () {
    if (this.isModified(propertyName)) {
      const salt = await bcrypt.genSalt(saltWorkFactor)
      this[propertyName] = await bcrypt.hash(this[propertyName], salt)
    }
  })

  schema.methods[methodName] = async function (candidate) {
    return bcrypt.compare(candidate, this[propertyName])
  }
}

module.exports = plugin
