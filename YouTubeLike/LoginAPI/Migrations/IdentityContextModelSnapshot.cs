﻿// <auto-generated />
using System;
using LoginAPI.Authentication;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace LoginAPI.Migrations
{
    [DbContext(typeof(IdentityContext))]
    partial class IdentityContextModelSnapshot : ModelSnapshot
    {
        protected override void BuildModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder
                .HasAnnotation("ProductVersion", "2.1.4-rtm-31024")
                .HasAnnotation("Relational:MaxIdentifierLength", 128)
                .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

            modelBuilder.Entity("LoginAPI.Authentication.Tables.Role", b =>
                {
                    b.Property<int>("RoleId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<string>("Description");

                    b.Property<int?>("Priority");

                    b.HasKey("RoleId");

                    b.ToTable("Roles");
                });

            modelBuilder.Entity("LoginAPI.Authentication.Tables.User", b =>
                {
                    b.Property<int>("UserId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<int>("CredentialsId");

                    b.Property<DateTime>("DateCreatedUTC");

                    b.Property<string>("Email");

                    b.Property<string>("FirstName");

                    b.Property<string>("LastName");

                    b.Property<string>("MiddleInit");

                    b.HasKey("UserId");

                    b.ToTable("Users");
                });

            modelBuilder.Entity("LoginAPI.Authentication.Tables.UserRole", b =>
                {
                    b.Property<int>("UserRoleId");

                    b.Property<int>("RoleId");

                    b.Property<int>("UserId");

                    b.HasKey("UserRoleId");

                    b.ToTable("UserRole");
                });

            modelBuilder.Entity("LoginAPI.Authentication.Tables.UserSecurity", b =>
                {
                    b.Property<int>("UserSecurityId")
                        .ValueGeneratedOnAdd()
                        .HasAnnotation("SqlServer:ValueGenerationStrategy", SqlServerValueGenerationStrategy.IdentityColumn);

                    b.Property<DateTime?>("DateLastAccessed");

                    b.Property<bool>("EmailVerified");

                    b.Property<int?>("PasswordChangeInterval");

                    b.Property<DateTime>("PasswordIssuedAtUTC");

                    b.Property<string>("SecurityHash");

                    b.Property<string>("SecuritySalt");

                    b.Property<int>("UserId");

                    b.HasKey("UserSecurityId");

                    b.HasIndex("UserId")
                        .IsUnique();

                    b.ToTable("Credentials");
                });

            modelBuilder.Entity("LoginAPI.Authentication.Tables.UserRole", b =>
                {
                    b.HasOne("LoginAPI.Authentication.Tables.Role", "Role")
                        .WithMany("Users")
                        .HasForeignKey("UserRoleId")
                        .OnDelete(DeleteBehavior.Cascade);

                    b.HasOne("LoginAPI.Authentication.Tables.User", "User")
                        .WithMany("Roles")
                        .HasForeignKey("UserRoleId")
                        .OnDelete(DeleteBehavior.Cascade);
                });

            modelBuilder.Entity("LoginAPI.Authentication.Tables.UserSecurity", b =>
                {
                    b.HasOne("LoginAPI.Authentication.Tables.User", "User")
                        .WithOne("Credentials")
                        .HasForeignKey("LoginAPI.Authentication.Tables.UserSecurity", "UserId")
                        .OnDelete(DeleteBehavior.Cascade);
                });
#pragma warning restore 612, 618
        }
    }
}
