using Mailjet.Client;
using Mailjet.Client.Resources;
using Mailjet.Client.TransactionalEmails;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;
using Newtonsoft.Json.Linq;

namespace IdentityManagerDemo.Services
{
    public class MailJetEmailSender : IEmailSender
    {
        private readonly IConfiguration config;
        private MailJetOptions _mailJetOptions;

        public MailJetEmailSender(IConfiguration config)
        {
            this.config=config;
            _mailJetOptions = new MailJetOptions();
        }
        public async Task SendEmailAsync(string email, string subject, string htmlMessage)
        {

            _mailJetOptions = config.GetSection("MailJet").Get<MailJetOptions>();

            MailjetClient client = new MailjetClient(_mailJetOptions.ApiKey, _mailJetOptions.SecretKey);

            // construct your email with builder
            var builder = new TransactionalEmailBuilder()
                   .WithFrom(new SendContact("jbmarvin@protonmail.com"))
                   .WithSubject(subject)
                   .WithHtmlPart(htmlMessage)
                   .WithTo(new SendContact(email: email))
                   .Build();

            // invoke API to send email
            await client.SendTransactionalEmailAsync(builder);
        }
    }
}
