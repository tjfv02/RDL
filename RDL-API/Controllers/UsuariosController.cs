using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using RDL_Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;


namespace RDL_API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UsuariosController : ControllerBase
    {
        private readonly string SecretKey;
        public UsuariosController(IConfiguration config)
        {
            SecretKey = config.GetSection("Settings").GetSection("SecretKey").ToString();
        }

        [HttpPost]
        [Route("ValidarToken")]
        public IActionResult Validar([FromBody] Usuario usuario) {
        
            //TODO: Hacer verificación del Match de Passwords
            if (usuario == null)
            {
                var KeyBytes = Encoding.ASCII.GetBytes(SecretKey);
                var claims = new ClaimsIdentity();

                claims.AddClaim(new Claim(ClaimTypes.NameIdentifier, usuario.Email));

                var TokenDescriptor = new SecurityTokenDescriptor
                {
                    Subject = claims,
                    Expires = DateTime.UtcNow.AddMinutes(5), //Tiempo de vencimiento
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(KeyBytes), SecurityAlgorithms.HmacSha256Signature)
                };

                var TokenHandler = new JwtSecurityTokenHandler();
                var TokenConfig = TokenHandler.CreateToken(TokenDescriptor);

                string TokenCreado = TokenHandler.WriteToken(TokenConfig);

                return StatusCode(StatusCodes.Status200OK, new { token = TokenCreado });
            }
            else
            {
                return StatusCode(StatusCodes.Status401Unauthorized, new { token = "NoAuth" });
            }
        }
    }
}
