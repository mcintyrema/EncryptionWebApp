using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Security.Cryptography;
using EncryptionWebApp.Models;

namespace EncryptionWebApp.Pages;

public class Index2Model : PageModel
{
    private readonly ILogger<Index2Model> _logger;

    public Index2Model(ILogger<Index2Model> logger)
    {
        _logger = logger;
    }

        [BindProperty]
        public string MethodChoice { get; set; }

        [BindProperty]
        public string TextInput { get; set; }

        [BindProperty]
        private string password {get; set;}

        [BindProperty]
        public string IV {get; set;}

        public string TextOutput { get; set; }

        public void OnGet()
        {

        }

        public IActionResult OnPost()
        {
            
                switch (MethodChoice)
                {
                    case "CaesarCipher":
                        TextOutput = CaesarCipherMethod.Decrypt(TextInput);
                        break;
                    case "DES":
                        TextOutput = DESMethod.Decrypt(TextInput);
                        break;
                    case "AES":
                        TextOutput = AESMethod.Decrypt(TextInput);
                        break;
                    case "VigenereCipher":
                        TextOutput = VinCipherMethod.Decrypt(TextInput);
                        break;
                    default:
                        Console.WriteLine("No method was specified.");
                        break;
                }
            
            return Page();
        }
    
}

