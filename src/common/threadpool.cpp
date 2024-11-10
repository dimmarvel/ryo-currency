// Copyright (c) 2020, Ryo Currency Project
// Portions copyright (c) 2014-2018, The Monero Project
//
// Portions of this file are available under BSD-3 license. Please see ORIGINAL-LICENSE for details
// All rights reserved.
//
// Authors and copyright holders give permission for following:
//
// 1. Redistribution and use in source and binary forms WITHOUT modification.
//
// 2. Modification of the source form for your own personal use.
//
// As long as the following conditions are met:
//
// 3. You must not distribute modified copies of the work to third parties. This includes
//    posting the work online, or hosting copies of the modified work for download.
//
// 4. Any derivative version of this work is also covered by this license, including point 8.
//
// 5. Neither the name of the copyright holders nor the names of the authors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
//
// 6. You agree that this licence is governed by and shall be construed in accordance
//    with the laws of England and Wales.
//
// 7. You agree to submit all disputes arising out of or in connection with this licence
//    to the exclusive jurisdiction of the Courts of England and Wales.
//
// Authors and copyright holders agree that:
//
// 8. This licence expires and the work covered by it is released into the
//    public domain on 1st of February 2021
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "common/threadpool.h"

#include <cassert>
#include <limits>
#include <stdexcept>

#include "common/util.h"
#include "cryptonote_config.h"

static __thread int depth = 0;
static __thread bool is_leaf = false;

namespace tools
{
threadpool::threadpool(unsigned int max_threads) : running(true), active(0) {
	create(max_threads);
}

threadpool::~threadpool() {
	destroy();
}

void threadpool::destroy() {
	try
	{
		const boost::unique_lock<boost::mutex> lock(mutex);
		running = false;
		has_work.notify_all();
	}
	catch (...)
	{
		// if the lock throws, we're just do it without a lock and hope,
		// since the alternative is terminate
		running = false;
		has_work.notify_all();
	}
	for (size_t i = 0; i<threads.size(); i++) {
		try { threads[i].join(); }
		catch (...) { /* ignore */ }
	}
	threads.clear();
}

void threadpool::recycle() {
	destroy();
	create(max);
}

void threadpool::create(unsigned int max_threads) {
	const boost::unique_lock<boost::mutex> lock(mutex);
	boost::thread::attributes attrs;
	attrs.set_stack_size(THREAD_STACK_SIZE);
	max = max_threads ? max_threads : tools::get_max_concurrency();
	size_t i = max ? max - 1 : 0;
	running = true;
	while(i--) {
		threads.push_back(boost::thread(attrs, boost::bind(&threadpool::run, this, false)));
	}
}

void threadpool::submit(waiter *obj, std::function<void()> f, bool leaf)
{
	boost::unique_lock<boost::mutex> lock(mutex);
	if (!leaf && ((active == max && !queue.empty()) || depth > 0)) {
		// if all available threads are already running
		// and there's work waiting, just run in current thread
		lock.unlock();
		++depth;
		is_leaf = leaf;
		f();
		--depth;
		is_leaf = false;
	} else {
		if (obj)
			obj->inc();
		if (leaf)
			queue.push_front({obj, f, leaf});
		else
			queue.push_back({obj, f, leaf});
		has_work.notify_one();
	}
}

int threadpool::get_max_concurrency()
{
	return max;
}

threadpool::waiter::~waiter()
{
	try
	{
		boost::unique_lock<boost::mutex> lock(mt);
		if (num)
			GULPS_ERROR("wait should have been called before waiter dtor - waiting now");
	}
	catch (...) { /* ignore */ }
	try
	{
		wait();
	}
	catch (const std::exception &e)
	{
		/* ignored */
	}
}

bool threadpool::waiter::wait()
{
	pool.run(true);
	boost::unique_lock<boost::mutex> lock(mt);
	while(num)
		cv.wait(lock);
	return !error();
}

void threadpool::waiter::inc()
{
	const boost::unique_lock<boost::mutex> lock(mt);
	num++;
}

void threadpool::waiter::dec()
{
	const boost::unique_lock<boost::mutex> lock(mt);
	num--;
	if(!num)
		cv.notify_one();
}

void threadpool::run(bool flush)
{
	boost::unique_lock<boost::mutex> lock(mutex);
	while (running) {
		entry e;
		while(queue.empty() && running)
		{
			if (flush)
				return;
			has_work.wait(lock);
		}
		if (!running) break;

		active++;
		e = std::move(queue.front());
		queue.pop_front();
		lock.unlock();
		++depth;
		is_leaf = e.leaf;
		try { e.f(); }
		catch (const std::exception &ex) { e.wo->set_error(); try { GULPSF_ERROR("Exception in threadpool job: {}", ex.what()); } catch (...) {} }
		--depth;
		is_leaf = false;

		if (e.wo)
			e.wo->dec();
		lock.lock();
		active--;
	}
	}
}
