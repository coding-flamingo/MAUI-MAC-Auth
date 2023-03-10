using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MAUIMACAuth.Models;

public class TokenResponseModel
{
    public string token_type { get; set; }
    public string scope { get; set; }
    public int expires_in { get; set; }
    public int ext_expires_in { get; set; }
    public string access_token { get; set; }
    public string refresh_token { get; set; }
    public DateTime expires_at { get; set; } = DateTime.UtcNow;
}
