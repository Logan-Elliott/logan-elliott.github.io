---
layout: post
title:  "WordPress to GitHub Pages: A New Beginning for My Website"
date: "2024-4-28"
author: "Logan Elliott"
excerpt: "In this post, I go over why GitHub Pages will be the new home for my blog, its many advantages, and why I kissed WordPress goodbye."
---

**Table of Contents**

* TOC
{:toc}

## Beginning My Blogging Journey

When I first started this blog back in 2019, there was a lot I didn’t know.

I did what most people in the field do when they start a blog: I read up on some guides, looked at other people’s blogs for inspiration, checked out some different documentation, weighed all of my options, and finally committed to a platform.

I decided to use WordPress as the CMS for my blog and SiteGround for my hosting and domain name.

At first, I was excited to jump in and begin building my very first blog. Then, as I started learning WordPress, I realized just how much more there was to manage and how time-consuming it would be. Nonetheless, I stuck with my decision; I was already committed and began writing some articles. As time passed, the issues became more and more apparent, and the cost of running my blog steadily increased.

So in this post, I will briefly go over why GitHub Pages will be the new home for my blog.

## WordPress Woes: The Problems With Using WordPress for Blogging

### WordPress Vulnerabilities

If you have been in infosec for any length of time, you will inevitably have encountered WordPress vulnerabilities.

Whether in the CMS itself, plugins, themes, PHP version, database version, etc.

Lmao even the plugin I used to export my content from WordPress to Jekyll was affected by a CVSS 9.8 RCE back in 2017:

<https://wpscan.com/plugin/jekyll-exporter/>{:target="_blank"}{:rel="noopener noreferrer"}

So many different vulnerabilities plague WordPress that it quickly becomes a nightmare trying to ensure you keep your site safe.

Yes, even as an infosec professional, it is time-consuming, and I found that this increased the time I spent administering my site so much that I didn’t even want, nor had the time, to focus on creating content.

Not to mention, as an ethical hacker who has compromised a great deal of WordPress sites throughout my career, the paranoia was unbearable. :confounded:

Is it impossible to secure WordPress? No, it’s just that it is not worth the time or money you will spend to do it as an independent blogger.

### User Input, Server-Side Language, and Databases

If you know the basics of web security, the majority of problems tend to be traced back to user input in some way or another.

So, by switching to a static website using GitHub Pages with Jekyll, we pretty much get rid of any user input as well as eliminate a database and server-side language.

This provides a **HUGE** boost to both security and speed.

No more worrying about SQLi, PHP code injection, etc. :raised_hands:

### Need for Speed :rocket:

WordPress has its use cases, but in my opinion, it’s quite overkill for blogging.

Do you really need to be serving blog posts dynamically to each user who visits your site? Probably not…

Using a static site for blogging provides much better performance and speed.

Some of the main reasons are:

* No server-side processing
* No database queries
* Easier caching

### Costs :moneybag:

Hosting a blog on GitHub Pages with Jekyll is literally ***FREE***.

Yes, actually, it’s really free.

Before, I was paying around $1000 USD a year for hosting, domain, web application firewall (WAF), licensing, etc.

Yea, that’s way too fucking expensive.

The only thing I will be paying for now is my domain, which is only $20 a year.

But if even that is out of your budget, GitHub Pages comes with a free domain for every user in the form of `<username>.github.io`.

Which probably works fine for most people.

### The Silver Lining

Look, WordPress isn't *ALL* bad okay.

It can be used to make amazing sites, and it has a wonderful community with plenty of great documentation.

While I would have saved a lot of money and a lot of worrying had I started my blog on GH Pages using Jekyll, to begin with, I don’t regret my decision to use WordPress for my first foray into blogging.

Yes, even with all my complaints!

Someone in this field made a post on Twitter a long time ago that has stuck with me to this day.

While I have forgotten who posted it or exactly how it was written, they basically said:

"There is no such thing as wasted time in infosec/IT."

This is true regarding this field, as well as life in general.

My time spent with WordPress, all the headaches and problems I had to solve, taught me ***SO MUCH*** about WordPress security, web security, web development, etc.

Truthfully, I am an even better hacker/infosec professional because of it.

But it is time for a change; so long, WordPress, and thanks for the learning experience!

## Why I Love GitHub Pages With Jekyll :heart_eyes:

Besides all the explanations listed above, here are some extra reasons why GitHub Pages with Jekyll kicks ass.

### Git Version Control

Git is one of the *BEST* things about using GH Pages with Jekyll.

Do you want to mess around with your site but are afraid you will mess everything up?

No worries, just discard changes since the last commit!

### Markdown

All content is written in Markdown, which is super convenient since I already use Markdown every day to take all my notes, write documentation, etc.

Whatever Markdown alone can’t handle, you can simply use inline HTML to compensate for it!

Making content has never been more seamless.

### Hacker Friendly

On top of already using Markdown, Jekyll has great documentation and allows plenty of customization.

You can really make your site your own with a bit of creativity and research.

I actually really enjoyed the process of customizing my Jekyll site/theme and learning more about how everything works by reading up on all the documentation and going through community posts.

Honestly, I feel the philosophy behind Jekyll and GitHub pages fits the hacker/learner mindset.

I plan to make a post soon sharing some of the tips and tricks I learned for customizing Jekyll with GH Pages to help some of you who may want to start your own blog. (If I get around to it, I get distracted easily.)

You can also use a different static site generator than Jekyll if you wish or pretty much do whatever you want with your GH Pages site by creating your own custom workflows with GitHub Actions.

### Easy SEO

Personally, I hate dealing with SEO.

It's obnoxious, and I really make this blog more for myself than to garner a bunch of traffic.

Jekyll makes SEO so easy it's laughable.

As long as you use the `jekyll-seo-tag` plugin, your content will automatically be optimized for SEO.

If you care about SEO, the most you might have to do now is run your headline through an SEO ranker.

Beforehand, I needed plugins such as MonsterInsights or Yoast SEO while using WordPress.

This is in addition to the million other things you must check off a list just to ensure your site isn’t buried at the bottom of Google search results.

Seriously, look up WordPress SEO, and you will see what I mean.

## The Future of This Blog

I could go on for days listing all the reasons I love GitHub Pages with Jekyll, but these are just some of the highlights.

For the reasons listed above and more, this will be the new home for my website. :house:

Given this change, I’ve decided to view this as a fresh new start for my blog.

There are some things I will be doing differently with my blog going forward:

1. **Focus on content over quality:** I feel that in the past, I would get carried away with writing and would spend too much time focusing on details, and let’s be honest, most of us aren’t going to read a post that is longer than the fucking *Magna Carta* whenever we are hacking into something. So, from now on, I will be making an effort to keep the majority of posts short and sweet.

2. **Grammar Nazi Punks Fuck Off:** That statement is actually quite self-deprecating, given that I am a bit of a grammar nazi myself (I read a lot, okay), but I simply do not have the time anymore to care. I have been told that I am a good writer; maybe I am or not. However, my last name ain't Tolstoy, and I’m done writing novels. If you couldn’t tell from the writing style in this post thus far, I will be keeping things cool and casual. :sunglasses:

3. **Posting More, Worrying Less:** When I first started my blog on WordPress, I was 19, and I think I was a bit too worried about how my content would be received. Well, I have grown a lot since then. I know much more about this field and what topics I enjoy studying and which I don’t. These days, I care much less about writing for an audience than writing for myself. I believe my blog should be a documentation of my own journey, passion, and love for what I do. It is ***still***, and ***always will be***, a goal of mine to share the knowledge and experiences I accumulate with others in this field, and this blog will still do that. I hope my writings here will help others, whether through my research, mistakes, tools, etc. However, I will focus on writing for myself first, and hopefully, some people will find value in what I share! :slightly_smiling_face:

I have decided to transfer only my most recent [post]({% post_url 2023-10-08-its-all-fud-and-games-undetectable-process-hollowing-on-windows %}){:target="_blank"}{:rel="noopener noreferrer"} from my previous WordPress blog to this new site.

Most of my old posts I don't care enough to spend the time transferring them over and formattting them properly. Like I said, this is going to be a fresh new start for this blog.

I might make an archive of my old posts from WordPress and leave a link to it somewhere in the future, but that is a project for a different day.

If you made it all the way to the end, congratulations, you're a real one. :tada: :100:

Have a cookie! :cookie:
