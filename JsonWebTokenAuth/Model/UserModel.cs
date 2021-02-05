using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace JsonWebTokenAuth.Model
{
    public class UserModel
    {
        public string Username { get; set; }
        public string Password { get; set; }
        public string EmailAddress { get; set; }
    }
}
