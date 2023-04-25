using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Cryptography;
using EncryptionWebApp.Models;

namespace EncryptionWebApp.Pages;

public class IndexModel : PageModel
{
    private readonly ILogger<IndexModel> _logger;

    public IndexModel(ILogger<IndexModel> logger)
    {
        _logger = logger;
    }

        [BindProperty]
        public string MethodChoice { get; set; }

        [BindProperty]
        public string TextInput { get; set; }

        [BindProperty]
        private string key {get; set;}

        public string TextOutput { get; set; }

        public void OnGet()
        {

        }

        public IActionResult OnPost()
        {
            
                switch (MethodChoice)
                {
                    case "CaesarCipher":
                        TextOutput = CaesarCipherMethod.Encrypt(TextInput);
                        break;
                    case "DES":
                        TextOutput = DESMethod.Encrypt(TextInput);
                        break;
                    case "AES":
                        TextOutput = AESMethod.Encrypt(TextInput);
                        break;
                    case "VigenereCipher":
                        TextOutput = VinCipherMethod.Encrypt(TextInput);
                        break;
                    default:
                        Console.WriteLine("No method was specified.");
                        break;
                }
            
            
                // switch (MethodChoice)
                // {
                //     case "caesarCipher":
                //         TextOutput = CaesarCipherMethod.Decrypt(TextInput);
                //         break;

                //     default:
                //         Console.WriteLine("No method was specified.");
                //         break;
                // }
            

            return Page();
        }
    
}

