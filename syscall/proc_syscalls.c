#include <types.h>
#include <kern/errno.h>
#include <kern/unistd.h>
#include <kern/wait.h>
#include <lib.h>
#include <syscall.h>
#include <current.h>
#include <proc.h>
#include <thread.h>
#include <addrspace.h>
#include <copyinout.h>
#include "opt-A2.h"
#include "opt-A3.h"
#include <limits.h>
#include <elf.h>

#include <synch.h>
#include <mips/trapframe.h>
#include <array.h>
#include <kern/fcntl.h>
#include <vfs.h>

struct array *pt; 
struct lock *lk_a2;

#if OPT_A2

void proc_table_cleanup(struct proc_table *p);
int sys_execv(const char *progname, userptr_t args);

int sys_fork(struct trapframe *tf, pid_t *retval) {
   struct proc *newp;
   newp = proc_create_runprogram(curproc->p_name);
   if (newp == NULL) {
    return ENOMEM;
   } else if (newp == (struct proc *)ENPROC) {
    return ENPROC;
   }

   lock_acquire(lk_a2);

   int ret = as_copy(curproc_getas(), &(newp->p_addrspace));
   if (ret != 0) {
    proc_table_cleanup(newp->t);
    proc_destroy(newp);
    lock_release(lk_a2);
    return ret;
   }

   //copy trapframe
   struct trapframe *ntf = kmalloc(sizeof(struct trapframe));
   if (ntf == NULL) {
    as_destroy(newp->p_addrspace);
    proc_table_cleanup(newp->t);
    proc_destroy(newp);
    lock_release(lk_a2);
    return ENOMEM;
  }

  memmove(ntf, tf, sizeof(struct trapframe));

  ntf->tf_v0 = 0;
  ntf->tf_epc += 4;
  lock_release(lk_a2);

  int r = thread_fork(curthread->t_name, newp, (void *)enter_forked_process, ntf, 0);
  if (r != 0) {
    lock_acquire(lk_a2);
    kfree(ntf);
    as_destroy(newp->p_addrspace);
    proc_table_cleanup(newp->t);
    proc_destroy(newp);
    lock_release(lk_a2);
    return r;
  }

  *retval = newp->t->pid;
  return 0;
}
#endif /* OPT_A2 */

void sys__exit(int exitcode) {

  struct addrspace *as;
  struct proc *p = curproc;
  /* for now, just include this to keep the compiler from complaining about
     an unused variable */
  //(void)exitcode;

  DEBUG(DB_SYSCALL,"Syscall: _exit(%d)\n",exitcode);
#if OPT_A2
  lock_acquire(lk_a2);
  curproc->t->exitcode = _MKWAIT_EXIT(exitcode); 
  curproc->t->exit_status = true;
  curproc->t->proc = NULL;

  unsigned int i = 0;
  struct proc_table *a = NULL;
  for (; i < array_num(pt); i++) {
    a = array_get(pt, i);
    if (a != NULL && a->parent == curproc && a->exit_status == true) {
      array_set(pt, a->pid - 2, NULL);
      kfree(a);
    } else if (a != NULL && a->parent == curproc && a->exit_status == false) {
      a->parent = NULL;
    }
  }

  if (curproc->t->parent == NULL || curproc->t->parent == kproc) {
    array_set (pt, curproc->t->pid - 2, NULL);
    kfree(curproc->t);
  } 

  cv_broadcast(curproc->cv, lk_a2);

  lock_release(lk_a2);
#else
  (void)exitcode;
#endif /* OPT_A2 */

  KASSERT(curproc->p_addrspace != NULL);
  as_deactivate();
  /*
   * clear p_addrspace before calling as_destroy. Otherwise if
   * as_destroy sleeps (which is quite possible) when we
   * come back we'll be calling as_activate on a
   * half-destroyed address space. This tends to be
   * messily fatal.
   */
  as = curproc_setas(NULL);
  as_destroy(as);

  /* detach this thread from its process */
  /* note: curproc cannot be used after this call */
  proc_remthread(curthread);

  /* if this is the last user process in the system, proc_destroy()
     will wake up the kernel menu thread */
  proc_destroy(p);
  
  thread_exit();
  /* thread_exit() does not return, so we should never get here */
  panic("return from thread_exit in sys_exit\n");
}




/* stub handler for getpid() system call                */
int
sys_getpid(pid_t *retval)
{
  /* for now, this is just a stub that always returns a PID of 1 */
  /* you need to fix this to make it work properly */
  //*retval = 1;
  //return(0);
  *retval = curproc->t->pid; 
  return 0;
}

/* stub handler for waitpid() system call                */

int
sys_waitpid(pid_t pid,
	    userptr_t status,
	    int options,
	    pid_t *retval)
{
  int exitstatus;
  int result;

  if (options != 0) {
    return(EINVAL);
  } 

#if OPT_A2
  if (pid > PID_MAX || pid < PID_MIN) {
    return ESRCH;
  } 

  //child of curproc?
  lock_acquire(lk_a2);
  if ((unsigned)pid-2 >= array_num(pt)){
    lock_release(lk_a2);
    return ESRCH;
  }
  struct proc_table * cpt = array_get(pt, pid - 2);
  if (cpt == NULL || cpt->parent != curproc) {
    lock_release(lk_a2);
    return ECHILD;
  }



  /* this is just a stub implementation that always reports an
     exit status of 0, regardless of the actual exit status of
     the specified process.   
     In fact, this will return 0 even if the specified process
     is still running, and even if it never existed in the first place.

     Fix this!
  */


  if (cpt->exit_status == false) {
    //lock_acquire(child->lk_cv);
    cv_wait(cpt->proc->cv, lk_a2);
    
  } 
  exitstatus = cpt->exitcode;

  proc_table_cleanup(cpt);
 
  lock_release(lk_a2);

#else
  /* for now, just pretend the exitstatus is 0 */
  exitstatus = 0;
#endif /* OPT_A2 */


  //parent get the exit status and exitcode of the child
  result = copyout((void *)&exitstatus,status,sizeof(int));
  if (result) {
   return(result);
  }
 *retval = pid; 
 return(0);    
}


 #if OPT_A2
void proc_table_cleanup(struct proc_table *p) {
  for (unsigned int i = 0; i < array_num(pt); i++ ) {
      struct proc_table * b = array_get(pt, i);
      if (b == p) { //found
        array_set(pt, i, NULL);
        break;
      }
    }
    kfree(p);
}


int
sys_execv(const char *progname, userptr_t args)
{
  (void) progname;

  struct array * array_args;
  int err1 = copyin(args, array_args, sizeof (userptr_t));
  if (err1) {
    return E2BIG;
  }

  
  return 0;

}


#endif


